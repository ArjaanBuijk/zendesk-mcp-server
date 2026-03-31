from typing import Dict, Any, List
import json
import os
import tempfile
import urllib.request
import urllib.parse
import base64
import requests as _requests

from zenpy import Zenpy
from zenpy.lib.api_objects import Comment
from zenpy.lib.api_objects import Ticket as ZenpyTicket


class ZendeskClient:
    def __init__(self, subdomain: str, email: str, token: str):
        """
        Initialize the Zendesk client using zenpy lib and direct API.
        """
        self.client = Zenpy(
            subdomain=subdomain,
            email=email,
            token=token
        )

        # For direct API calls
        self.subdomain = subdomain
        self.email = email
        self.token = token
        self.base_url = f"https://{subdomain}.zendesk.com/api/v2"
        # Create basic auth header
        credentials = f"{email}/token:{token}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode('ascii')
        self.auth_header = f"Basic {encoded_credentials}"

    def get_ticket(self, ticket_id: int) -> Dict[str, Any]:
        """
        Query a ticket by its ID
        """
        try:
            ticket = self.client.tickets(id=ticket_id)
            org_id = ticket.organization_id
            org_name = None
            if org_id:
                org_names = self._resolve_organization_names([org_id])
                org_name = org_names.get(org_id)
            return {
                'id': ticket.id,
                'subject': ticket.subject,
                'description': ticket.description,
                'status': ticket.status,
                'priority': ticket.priority,
                'created_at': str(ticket.created_at),
                'updated_at': str(ticket.updated_at),
                'requester_id': ticket.requester_id,
                'assignee_id': ticket.assignee_id,
                'organization_id': org_id,
                'organization_name': org_name,
            }
        except Exception as e:
            raise Exception(f"Failed to get ticket {ticket_id}: {str(e)}")

    _MAX_COMMENT_BODY_LENGTH = 2000

    def get_ticket_comments(self, ticket_id: int) -> Dict[str, Any]:
        """
        Get all comments for a specific ticket, including attachment metadata.
        Returns a dict with summary metadata and a list of comments.
        Long comment bodies are truncated to reduce response size.
        """
        try:
            comments = self.client.tickets.comments(ticket=ticket_id)
            result = []
            for comment in comments:
                attachments = []
                for a in getattr(comment, 'attachments', []) or []:
                    attachments.append({
                        'id': a.id,
                        'file_name': a.file_name,
                        'content_url': a.content_url,
                        'content_type': a.content_type,
                        'size': a.size,
                    })
                body = comment.body or ''
                truncated = len(body) > self._MAX_COMMENT_BODY_LENGTH
                if truncated:
                    body = body[:self._MAX_COMMENT_BODY_LENGTH] + '… [truncated]'
                result.append({
                    'id': comment.id,
                    'author_id': comment.author_id,
                    'body': body,
                    'public': comment.public,
                    'created_at': str(comment.created_at),
                    'attachments': attachments,
                })
            dates = [c['created_at'] for c in result]
            return {
                'ticket_id': ticket_id,
                'total_comments': len(result),
                'first_comment_at': dates[0] if dates else None,
                'last_comment_at': dates[-1] if dates else None,
                'comments': result,
            }
        except Exception as e:
            raise Exception(f"Failed to get comments for ticket {ticket_id}: {str(e)}")

    # Allowed MIME types for attachments.
    _ALLOWED_IMAGE_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'image/webp'}
    _ALLOWED_TEXT_TYPES = {
        'text/plain', 'text/csv', 'text/html', 'text/xml',
        'application/json', 'application/xml',
        'application/x-yaml', 'text/yaml',
    }
    _ALLOWED_BINARY_TYPES = {
        'application/zip', 'application/gzip', 'application/x-gzip',
        'application/x-tar', 'application/x-compressed-tar',
        'application/pdf',
        'application/octet-stream',
    }
    _ALLOWED_TYPES = _ALLOWED_IMAGE_TYPES | _ALLOWED_TEXT_TYPES | _ALLOWED_BINARY_TYPES

    # Magic bytes (file signatures) for image types.
    _MAGIC_BYTES: Dict[str, List[bytes]] = {
        'image/jpeg': [b'\xff\xd8\xff'],
        'image/png':  [b'\x89PNG\r\n\x1a\n'],
        'image/gif':  [b'GIF87a', b'GIF89a'],
        'image/webp': [b'RIFF'],  # RIFF....WEBP — checked further below
    }

    # 10 MB hard cap to guard against image bombs and token budget blowout.
    _MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024

    def get_ticket_attachment(self, content_url: str) -> Dict[str, Any]:
        """
        Fetch an attachment and return its content.

        Images are returned as base64-encoded data.
        Text files are returned as plain text (UTF-8 decoded).

        Security measures applied:
        - Allowlist of safe MIME types (no SVG or arbitrary binary).
        - Magic byte validation for image types.
        - 10 MB size cap.

        Zendesk attachment URLs redirect to zdusercontent.com (Zendesk's CDN).
        requests strips the Authorization header on cross-origin redirects,
        which is required — the CDN returns 403 if it receives an auth header.
        """
        try:
            response = _requests.get(
                content_url,
                headers={'Authorization': self.auth_header},
                timeout=30,
                stream=True,
            )
            response.raise_for_status()

            content_type = response.headers.get('Content-Type', '').split(';')[0].strip().lower()

            if content_type not in self._ALLOWED_TYPES:
                raise ValueError(
                    f"Attachment type '{content_type}' is not allowed. "
                    f"Supported types: {sorted(self._ALLOWED_TYPES)}"
                )

            # Read with size cap — stops download as soon as limit is exceeded.
            chunks = []
            total = 0
            for chunk in response.iter_content(chunk_size=65536):
                total += len(chunk)
                if total > self._MAX_ATTACHMENT_BYTES:
                    raise ValueError(
                        f"Attachment exceeds the {self._MAX_ATTACHMENT_BYTES // (1024*1024)} MB size limit."
                    )
                chunks.append(chunk)
            content = b''.join(chunks)

            # For text types, decode and return as plain text.
            if content_type in self._ALLOWED_TEXT_TYPES:
                return {
                    'data': content.decode('utf-8', errors='replace'),
                    'content_type': content_type,
                }

            # For binary types, save to temp file and return the path.
            if content_type in self._ALLOWED_BINARY_TYPES:
                # Extract filename from URL query param or use a default.
                filename = 'attachment'
                if 'name=' in content_url:
                    from urllib.parse import urlparse, parse_qs
                    qs = parse_qs(urlparse(content_url).query)
                    if 'name' in qs:
                        filename = qs['name'][0]
                tmpdir = os.path.join(tempfile.gettempdir(), 'zendesk-attachments')
                os.makedirs(tmpdir, exist_ok=True)
                filepath = os.path.join(tmpdir, filename)
                with open(filepath, 'wb') as f:
                    f.write(content)
                return {
                    'data': filepath,
                    'content_type': content_type,
                    'saved_to_disk': True,
                }

            # Validate magic bytes for images to catch MIME type spoofing.
            magic_signatures = self._MAGIC_BYTES.get(content_type, [])
            if magic_signatures and not any(content.startswith(sig) for sig in magic_signatures):
                raise ValueError(
                    f"File header does not match declared content type '{content_type}'. "
                    "The attachment may be spoofed."
                )
            # Extra check for WebP: bytes 8–12 must be b'WEBP'.
            if content_type == 'image/webp' and content[8:12] != b'WEBP':
                raise ValueError("File header does not match declared content type 'image/webp'.")

            return {
                'data': base64.b64encode(content).decode('ascii'),
                'content_type': content_type,
            }
        except (ValueError, _requests.HTTPError):
            raise
        except Exception as e:
            raise Exception(f"Failed to fetch attachment from {content_url}: {str(e)}")

    def post_comment(self, ticket_id: int, comment: str, public: bool = True) -> str:
        """
        Post a comment to an existing ticket.
        """
        try:
            ticket = self.client.tickets(id=ticket_id)
            ticket.comment = Comment(
                html_body=comment,
                public=public
            )
            self.client.tickets.update(ticket)
            return comment
        except Exception as e:
            raise Exception(f"Failed to post comment on ticket {ticket_id}: {str(e)}")

    def _resolve_organization_names(self, org_ids: List[int]) -> Dict[int, str]:
        """Resolve a list of organization IDs to names via Zenpy."""
        org_names: Dict[int, str] = {}
        for org_id in org_ids:
            try:
                org = self.client.organizations(id=org_id)
                org_names[org_id] = org.name
            except Exception:
                org_names[org_id] = f"org-{org_id}"
        return org_names

    def get_tickets(
        self,
        page: int = 1,
        per_page: int = 25,
        sort_by: str = 'created_at',
        sort_order: str = 'desc',
        status: str | None = None,
        organization: str | None = None,
        created_after: str | None = None,
    ) -> Dict[str, Any]:
        """
        Get tickets with pagination, optional filters, and organization names.

        Args:
            page: Page number (1-based)
            per_page: Number of tickets per page (max 100)
            sort_by: Field to sort by (created_at, updated_at, priority, status)
            sort_order: Sort order (asc or desc)
            status: Optional status filter (new, open, pending, on-hold, solved, closed)
            organization: Optional organization/company name filter
            created_after: Optional date filter (YYYY-MM-DD), returns tickets created after this date

        Returns:
            Dict containing tickets (with organization_name) and pagination info
        """
        try:
            per_page = min(per_page, 100)

            if status or organization or created_after:
                # Use Search API for server-side filtering
                query_parts = ["type:ticket"]
                if status:
                    query_parts.append(f"status:{status}")
                if organization:
                    query_parts.append(f'organization:"{organization}"')
                if created_after:
                    query_parts.append(f"created>{created_after}")
                query = " ".join(query_parts)
                params = {
                    'query': query,
                    'page': str(page),
                    'per_page': str(per_page),
                    'sort_by': sort_by,
                    'sort_order': sort_order,
                }
                query_string = urllib.parse.urlencode(params)
                url = f"{self.base_url}/search.json?{query_string}"
            else:
                params = {
                    'page': str(page),
                    'per_page': str(per_page),
                    'sort_by': sort_by,
                    'sort_order': sort_order,
                }
                query_string = urllib.parse.urlencode(params)
                url = f"{self.base_url}/tickets.json?{query_string}"

            req = urllib.request.Request(url)
            req.add_header('Authorization', self.auth_header)
            req.add_header('Content-Type', 'application/json')

            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())

            # Search API uses 'results', tickets API uses 'tickets'
            tickets_data = data.get('results') or data.get('tickets', [])

            # Collect unique org IDs and resolve names
            org_ids = {
                t.get('organization_id')
                for t in tickets_data
                if t.get('organization_id')
            }
            org_names = self._resolve_organization_names(list(org_ids)) if org_ids else {}

            ticket_list = []
            for ticket in tickets_data:
                org_id = ticket.get('organization_id')
                ticket_list.append({
                    'id': ticket.get('id'),
                    'subject': ticket.get('subject'),
                    'status': ticket.get('status'),
                    'priority': ticket.get('priority'),
                    'created_at': ticket.get('created_at'),
                    'updated_at': ticket.get('updated_at'),
                    'requester_id': ticket.get('requester_id'),
                    'assignee_id': ticket.get('assignee_id'),
                    'organization_id': org_id,
                    'organization_name': org_names.get(org_id) if org_id else None,
                })

            return {
                'tickets': ticket_list,
                'page': page,
                'per_page': per_page,
                'count': len(ticket_list),
                'sort_by': sort_by,
                'sort_order': sort_order,
                'status_filter': status,
                'has_more': data.get('next_page') is not None,
                'next_page': page + 1 if data.get('next_page') else None,
                'previous_page': page - 1 if data.get('previous_page') and page > 1 else None,
            }
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.fp else "No response body"
            raise Exception(f"Failed to get tickets: HTTP {e.code} - {e.reason}. {error_body}")
        except Exception as e:
            raise Exception(f"Failed to get tickets: {str(e)}")

    def get_all_articles(self) -> Dict[str, Any]:
        """
        Fetch help center articles as knowledge base.
        Returns a Dict of section -> [article].
        """
        try:
            # Get all sections
            sections = self.client.help_center.sections()

            # Get articles for each section
            kb = {}
            for section in sections:
                articles = self.client.help_center.sections.articles(section.id)
                kb[section.name] = {
                    'section_id': section.id,
                    'description': section.description,
                    'articles': [{
                        'id': article.id,
                        'title': article.title,
                        'body': article.body,
                        'updated_at': str(article.updated_at),
                        'url': article.html_url
                    } for article in articles]
                }

            return kb
        except Exception as e:
            raise Exception(f"Failed to fetch knowledge base: {str(e)}")

    def create_ticket(
        self,
        subject: str,
        description: str,
        requester_id: int | None = None,
        assignee_id: int | None = None,
        priority: str | None = None,
        type: str | None = None,
        tags: List[str] | None = None,
        custom_fields: List[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        """
        Create a new Zendesk ticket using Zenpy and return essential fields.

        Args:
            subject: Ticket subject
            description: Ticket description (plain text). Will also be used as initial comment.
            requester_id: Optional requester user ID
            assignee_id: Optional assignee user ID
            priority: Optional priority (low, normal, high, urgent)
            type: Optional ticket type (problem, incident, question, task)
            tags: Optional list of tags
            custom_fields: Optional list of dicts: {id: int, value: Any}
        """
        try:
            ticket = ZenpyTicket(
                subject=subject,
                description=description,
                requester_id=requester_id,
                assignee_id=assignee_id,
                priority=priority,
                type=type,
                tags=tags,
                custom_fields=custom_fields,
            )
            created_audit = self.client.tickets.create(ticket)
            # Fetch created ticket id from audit
            created_ticket_id = getattr(getattr(created_audit, 'ticket', None), 'id', None)
            if created_ticket_id is None:
                # Fallback: try to read id from audit events
                created_ticket_id = getattr(created_audit, 'id', None)

            # Fetch full ticket to return consistent data
            created = self.client.tickets(id=created_ticket_id) if created_ticket_id else None

            return {
                'id': getattr(created, 'id', created_ticket_id),
                'subject': getattr(created, 'subject', subject),
                'description': getattr(created, 'description', description),
                'status': getattr(created, 'status', 'new'),
                'priority': getattr(created, 'priority', priority),
                'type': getattr(created, 'type', type),
                'created_at': str(getattr(created, 'created_at', '')),
                'updated_at': str(getattr(created, 'updated_at', '')),
                'requester_id': getattr(created, 'requester_id', requester_id),
                'assignee_id': getattr(created, 'assignee_id', assignee_id),
                'organization_id': getattr(created, 'organization_id', None),
                'tags': list(getattr(created, 'tags', tags or []) or []),
            }
        except Exception as e:
            raise Exception(f"Failed to create ticket: {str(e)}")

    def update_ticket(self, ticket_id: int, **fields: Any) -> Dict[str, Any]:
        """
        Update a Zendesk ticket with provided fields using Zenpy.

        Supported fields include common ticket attributes like:
        subject, status, priority, type, assignee_id, requester_id,
        tags (list[str]), custom_fields (list[dict]), due_at, etc.
        """
        try:
            # Load the ticket, mutate fields directly, and update
            ticket = self.client.tickets(id=ticket_id)
            for key, value in fields.items():
                if value is None:
                    continue
                setattr(ticket, key, value)

            # This call returns a TicketAudit (not a Ticket). Don't read attrs from it.
            self.client.tickets.update(ticket)

            # Fetch the fresh ticket to return consistent data
            refreshed = self.client.tickets(id=ticket_id)

            return {
                'id': refreshed.id,
                'subject': refreshed.subject,
                'description': refreshed.description,
                'status': refreshed.status,
                'priority': refreshed.priority,
                'type': getattr(refreshed, 'type', None),
                'created_at': str(refreshed.created_at),
                'updated_at': str(refreshed.updated_at),
                'requester_id': refreshed.requester_id,
                'assignee_id': refreshed.assignee_id,
                'organization_id': refreshed.organization_id,
                'tags': list(getattr(refreshed, 'tags', []) or []),
            }
        except Exception as e:
            raise Exception(f"Failed to update ticket {ticket_id}: {str(e)}")