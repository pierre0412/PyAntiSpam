"""Email client for IMAP operations"""

import imaplib
import email
import ssl
import time
from typing import List, Dict, Any, Optional, Tuple
from email.message import EmailMessage
import logging


class EmailClient:
    """IMAP email client for spam detection operations"""

    def __init__(self, server: str, port: int, username: str, password: str, use_ssl: bool = True, request_delay: float = 0.1):
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.imap = None
        self.current_folder = "INBOX"
        self.logger = logging.getLogger(__name__)
        self.request_delay = request_delay  # Delay between requests in seconds
        self.last_request_time = 0

    def _throttle_request(self):
        """Enforce rate limiting by adding delays between requests"""
        if self.request_delay <= 0:
            return
            
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.request_delay:
            sleep_time = self.request_delay - time_since_last
            self.logger.debug(f"Rate limiting: sleeping {sleep_time:.3f}s")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()

    def connect(self) -> bool:
        """Connect to the IMAP server"""
        try:
            if self.use_ssl:
                self.imap = imaplib.IMAP4_SSL(self.server, self.port)
            else:
                self.imap = imaplib.IMAP4(self.server, self.port)

            self.imap.login(self.username, self.password)
            self.logger.info(f"Connected to {self.server} for {self.username}")
            return True

        except imaplib.IMAP4.error as e:
            self.logger.error(f"IMAP connection failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during connection: {e}")
            return False

    def disconnect(self):
        """Disconnect from the IMAP server"""
        if self.imap:
            try:
                # First try to close the connection gracefully
                self.imap.close()
            except Exception as e:
                # Ignore close errors, we'll still try logout
                self.logger.debug(f"Error during close: {e}")
            
            try:
                # Try to logout normally
                self.imap.logout()
                self.logger.info(f"Disconnected from {self.server}")
            except (ssl.SSLError, OSError) as e:
                # Handle SSL-specific errors and broken pipe errors gracefully
                if "BAD_LENGTH" in str(e) or "bad length" in str(e).lower():
                    self.logger.debug(f"SSL disconnect issue handled gracefully: {e}")
                elif hasattr(e, 'errno') and e.errno == 32:  # Broken pipe
                    self.logger.debug(f"Broken pipe during disconnect handled gracefully: {e}")
                elif "Broken pipe" in str(e) or "[Errno 32]" in str(e):
                    self.logger.debug(f"Broken pipe during disconnect handled gracefully: {e}")
                else:
                    self.logger.warning(f"Socket error during disconnect: {e}")
            except Exception as e:
                # Check if this is a broken pipe error that wasn't caught by the OSError handler
                if (getattr(e, 'errno', None) == 32) or \
                   "Broken pipe" in str(e) or "[Errno 32]" in str(e) or \
                   "broken pipe" in str(e).lower():
                    self.logger.debug(f"Broken pipe during disconnect handled gracefully: {e}")
                else:
                    self.logger.warning(f"Error during disconnect: {e}")
            finally:
                # Ensure the connection is cleaned up
                try:
                    if hasattr(self.imap, 'sock') and self.imap.sock:
                        self.imap.sock.close()
                except Exception:
                    pass  # Ignore socket cleanup errors
                self.imap = None

    def select_folder(self, folder: str = "INBOX") -> bool:
        """Select email folder"""
        if not self.imap:
            raise ConnectionError("Not connected to IMAP server")

        try:
            self._throttle_request()
            status, data = self.imap.select(folder)
            if status == "OK":
                self.current_folder = folder
                self.logger.debug(f"Selected folder: {folder}")
                return True
            else:
                self.logger.error(f"Failed to select folder {folder}: {data}")
                return False
        except Exception as e:
            self.logger.error(f"Error selecting folder {folder}: {e}")
            return False

    def get_email_ids(self, search_criteria: str = "ALL") -> List[str]:
        """Get list of email IDs based on search criteria"""
        # Use the safer method by default
        return self.get_email_ids_safe(search_criteria)

    def get_email_ids_basic(self, search_criteria: str = "ALL") -> List[str]:
        """Basic email ID retrieval without extra safety checks"""
        if not self.imap:
            raise ConnectionError("Not connected to IMAP server")

        try:
            self._throttle_request()
            status, data = self.imap.search(None, search_criteria)
            if status == "OK":
                email_ids = data[0].split()
                return [email_id.decode() for email_id in email_ids]
            else:
                self.logger.error(f"Search failed: {data}")
                return []
        except Exception as e:
            self.logger.error(f"Error searching emails: {e}")
            return []

    def fetch_email(self, email_id: str) -> Optional[Dict[str, Any]]:
        """Fetch email by ID and return parsed data, preserving unread status"""
        if not self.imap:
            raise ConnectionError("Not connected to IMAP server")

        try:
            # Validate email ID first
            if not self._is_valid_email_id(email_id):
                self.logger.warning(f"Invalid email ID: {email_id}")
                return None

            # Check if email was unread before fetching (this preserves the status)
            was_unread = self.is_email_unread(email_id)

            self._throttle_request()
            status, data = self.imap.fetch(email_id, "(RFC822)")
            if status != "OK":
                self.logger.warning(f"Email {email_id} no longer exists or is invalid")
                return None

            # Check if we actually got data
            if not data or not data[0] or len(data[0]) < 2:
                self.logger.warning(f"No data returned for email {email_id}")
                return None

            raw_email = data[0][1]
            email_message = email.message_from_bytes(raw_email)

            # Parse the email data
            email_data = self._parse_email(email_message, email_id)

            # Add unread status to email data
            if email_data:
                email_data['was_unread'] = was_unread

                # If the email was unread before fetching, mark it back as unread
                if was_unread:
                    self.mark_email_unread(email_id)
                    self.logger.debug(f"Preserved unread status for email {email_id}")

            return email_data

        except Exception as e:
            self.logger.warning(f"Error fetching email {email_id}: {e}")
            return None

    def _parse_email(self, email_message: EmailMessage, email_id: str) -> Dict[str, Any]:
        """Parse email message into structured data"""
        # Extract sender information
        sender = email_message.get("From", "")
        sender_email = self._extract_email_address(sender)
        sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""

        # Extract basic headers
        subject = email_message.get("Subject", "")
        date = email_message.get("Date", "")
        to = email_message.get("To", "")
        cc = email_message.get("Cc", "")

        # Extract body content
        body = self._extract_body(email_message)

        return {
            "id": email_id,
            "sender": sender,
            "sender_email": sender_email,
            "sender_domain": sender_domain,
            "subject": subject,
            "date": date,
            "to": to,
            "cc": cc,
            "body": body,
            "raw_headers": dict(email_message.items())
        }

    def _extract_email_address(self, sender_field: str) -> str:
        """Extract email address from sender field"""
        import re
        # Simple regex to extract email from "Name <email@domain.com>" format
        match = re.search(r'<(.+?)>', sender_field)
        if match:
            return match.group(1)

        # If no brackets, check if it's just an email
        if "@" in sender_field:
            return sender_field.strip()

        return ""

    def _extract_body(self, email_message: EmailMessage) -> str:
        """Extract body text from email message"""
        body = ""

        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_type() == "text/plain":
                    body += part.get_payload(decode=True).decode("utf-8", errors="ignore")
        else:
            body = email_message.get_payload(decode=True).decode("utf-8", errors="ignore")

        return body

    def move_email_to_folder(self, email_id: str, target_folder: str) -> bool:
        """Move email to specified folder"""
        if not self.imap:
            raise ConnectionError("Not connected to IMAP server")

        try:
            # Normalize folder name for this server
            normalized_folder = self._normalize_folder_name(target_folder)

            # Create folder if it doesn't exist
            self._create_folder_if_not_exists(normalized_folder)

            # Copy email to target folder
            status, data = self.imap.copy(email_id, normalized_folder)
            if status != "OK":
                self.logger.error(f"Failed to copy email {email_id} to {normalized_folder}: {data}")
                return False

            # Mark original email as deleted
            self.imap.store(email_id, "+FLAGS", "\\Deleted")

            # Expunge to actually delete
            self.imap.expunge()

            self.logger.info(f"Moved email {email_id} to {normalized_folder}")
            return True

        except Exception as e:
            self.logger.error(f"Error moving email {email_id} to {normalized_folder}: {e}")
            return False

    def _create_folder_if_not_exists(self, folder_name: str):
        """Create folder if it doesn't exist"""
        try:
            status, folders = self.imap.list()
            existing_folders = [folder.decode().split('"')[-2] for folder in folders]

            if folder_name not in existing_folders:
                self.imap.create(folder_name)
                self.logger.info(f"Created folder: {folder_name}")
        except Exception as e:
            self.logger.warning(f"Could not create/check folder {folder_name}: {e}")

    def delete_email(self, email_id: str) -> bool:
        """Delete email permanently"""
        if not self.imap:
            raise ConnectionError("Not connected to IMAP server")

        try:
            # Mark email as deleted
            self.imap.store(email_id, "+FLAGS", "\\Deleted")

            # Expunge to actually delete
            self.imap.expunge()

            self.logger.info(f"Deleted email {email_id}")
            return True

        except Exception as e:
            self.logger.error(f"Error deleting email {email_id}: {e}")
            return False

    def get_folder_list(self) -> List[str]:
        """Get list of available folders"""
        if not self.imap:
            raise ConnectionError("Not connected to IMAP server")

        try:
            status, folders = self.imap.list()
            if status == "OK":
                folder_names = []
                for folder in folders:
                    # Parse folder name from IMAP response
                    folder_info = folder.decode()
                    folder_name = folder_info.split('"')[-2]
                    folder_names.append(folder_name)
                return folder_names
            else:
                self.logger.error(f"Failed to get folder list: {folders}")
                return []
        except Exception as e:
            self.logger.error(f"Error getting folder list: {e}")
            return []

    def cleanup_old_spam(self, spam_folder: str, days_threshold: int) -> int:
        """Delete emails older than threshold from spam folder"""
        if not self.imap:
            raise ConnectionError("Not connected to IMAP server")

        if days_threshold <= 0:
            self.logger.debug("Auto-delete disabled (days_threshold <= 0)")
            return 0

        try:
            # Create folder if it doesn't exist
            self._create_folder_if_not_exists(spam_folder)

            # Select spam folder
            status, _ = self.imap.select(spam_folder)
            if status != "OK":
                self.logger.warning(f"Cannot access spam folder '{spam_folder}' for cleanup")
                return 0

            # Calculate cutoff date
            from datetime import datetime, timedelta
            cutoff_date = datetime.now() - timedelta(days=days_threshold)
            cutoff_str = cutoff_date.strftime("%d-%b-%Y")

            # Search for emails older than cutoff date
            status, email_ids = self.imap.search(None, f'BEFORE "{cutoff_str}"')
            if status != "OK":
                self.logger.warning(f"Search failed in spam folder '{spam_folder}'")
                return 0

            if not email_ids or not email_ids[0]:
                self.logger.debug(f"No old emails found in spam folder '{spam_folder}'")
                return 0

            # Get list of email IDs to delete
            old_email_ids = email_ids[0].decode().split()
            deleted_count = 0

            for email_id in old_email_ids:
                try:
                    # Mark as deleted
                    self.imap.store(email_id, "+FLAGS", "\\Deleted")
                    deleted_count += 1
                except Exception as e:
                    self.logger.warning(f"Failed to mark email {email_id} for deletion: {e}")

            # Expunge to actually delete
            if deleted_count > 0:
                self.imap.expunge()
                self.logger.info(f"Auto-deleted {deleted_count} old emails from spam folder '{spam_folder}'")

            return deleted_count

        except Exception as e:
            self.logger.error(f"Error during spam cleanup: {e}")
            return 0
        finally:
            # Return to INBOX
            try:
                self.imap.select("INBOX")
            except:
                pass

    def _normalize_folder_name(self, folder_name: str) -> str:
        """Normalize folder name based on server conventions"""
        if not folder_name or folder_name == "INBOX":
            return folder_name

        # If folder already has INBOX prefix, return as-is
        if folder_name.startswith("INBOX."):
            return folder_name

        # Get folder list to detect server naming convention
        try:
            existing_folders = self.get_folder_list()

            # Check if server uses INBOX. prefix for subfolders
            has_inbox_prefix = any(f.startswith("INBOX.") for f in existing_folders if f != "INBOX")

            if has_inbox_prefix:
                # Use INBOX. prefix for new folders
                return f"INBOX.{folder_name}"
            else:
                # Server doesn't use INBOX prefix
                return folder_name

        except Exception as e:
            self.logger.warning(f"Could not detect folder naming convention: {e}")
            # Default: try INBOX. prefix as suggested by error message
            return f"INBOX.{folder_name}"

    def _is_valid_email_id(self, email_id: str) -> bool:
        """Validate email ID format and existence"""
        try:
            # Check if it's a valid number
            if not email_id.isdigit():
                return False

            # Check if ID exists by doing a quick exists check
            status, data = self.imap.fetch(email_id, "(UID)")
            return status == "OK"

        except Exception:
            return False

    def is_email_unread(self, email_id: str) -> bool:
        """Check if an email is unread (has UNSEEN flag)"""
        if not self.imap:
            return False

        try:
            self._throttle_request()
            status, data = self.imap.fetch(email_id, "(FLAGS)")
            if status == "OK" and data and data[0]:
                flags_response = data[0].decode()
                # Check if UNSEEN flag is NOT present (email is read) or IS present (email is unread)
                return "\\Seen" not in flags_response
            return False
        except Exception as e:
            self.logger.debug(f"Error checking unread status for email {email_id}: {e}")
            return False

    def mark_email_unread(self, email_id: str) -> bool:
        """Mark an email as unread by removing the SEEN flag"""
        if not self.imap:
            return False

        try:
            self._throttle_request()
            status, data = self.imap.store(email_id, "-FLAGS", "\\Seen")
            if status == "OK":
                self.logger.debug(f"Marked email {email_id} as unread")
                return True
            else:
                self.logger.warning(f"Failed to mark email {email_id} as unread: {data}")
                return False
        except Exception as e:
            self.logger.error(f"Error marking email {email_id} as unread: {e}")
            return False

    def mark_email_read(self, email_id: str) -> bool:
        """Mark an email as read by adding the SEEN flag"""
        if not self.imap:
            return False

        try:
            self._throttle_request()
            status, data = self.imap.store(email_id, "+FLAGS", "\\Seen")
            if status == "OK":
                self.logger.debug(f"Marked email {email_id} as read")
                return True
            else:
                self.logger.warning(f"Failed to mark email {email_id} as read: {data}")
                return False
        except Exception as e:
            self.logger.error(f"Error marking email {email_id} as read: {e}")
            return False

    def get_email_ids_safe(self, search_criteria: str = "ALL") -> List[str]:
        """Get list of valid email IDs with additional safety checks"""
        if not self.imap:
            raise ConnectionError("Not connected to IMAP server")

        try:
            # First, get the current folder status
            self._throttle_request()
            status, data = self.imap.status(self.current_folder, "(MESSAGES)")
            if status != "OK":
                self.logger.warning(f"Could not get folder status: {data}")

            self._throttle_request()
            status, data = self.imap.search(None, search_criteria)
            if status == "OK":
                email_ids = data[0].split()
                valid_ids = []

                for email_id in email_ids:
                    email_id_str = email_id.decode()
                    # Quick validation
                    if email_id_str.isdigit():
                        valid_ids.append(email_id_str)
                    else:
                        self.logger.warning(f"Skipping invalid email ID: {email_id_str}")

                self.logger.info(f"Found {len(valid_ids)} valid emails matching '{search_criteria}'")
                return valid_ids
            else:
                self.logger.error(f"Search failed: {data}")
                return []

        except Exception as e:
            self.logger.error(f"Error searching emails: {e}")
            return []