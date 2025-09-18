"""Whitelist and blacklist management"""

import json
import os
from pathlib import Path
from typing import Set, Dict, List, Optional
from email_validator import validate_email, EmailNotValidError
import logging


class ListManager:
    """Manages whitelist and blacklist for email filtering"""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)

        self.whitelist_file = self.data_dir / "whitelist.json"
        self.blacklist_file = self.data_dir / "blacklist.json"

        self.whitelist: Dict[str, Set[str]] = {"emails": set(), "domains": set()}
        self.blacklist: Dict[str, Set[str]] = {"emails": set(), "domains": set()}

        self.logger = logging.getLogger(__name__)
        self._load_lists()

    def _load_lists(self):
        """Load whitelist and blacklist from files"""
        try:
            self._load_list_file(self.whitelist_file, self.whitelist)
            self._load_list_file(self.blacklist_file, self.blacklist)
            self.logger.info("Loaded whitelist and blacklist")
        except Exception as e:
            self.logger.warning(f"Error loading lists: {e}")

    def _load_list_file(self, file_path: Path, target_dict: Dict[str, Set[str]]):
        """Load a single list file"""
        if file_path.exists():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    target_dict["emails"] = set(data.get("emails", []))
                    target_dict["domains"] = set(data.get("domains", []))
            except (json.JSONDecodeError, KeyError) as e:
                self.logger.error(f"Error parsing {file_path}: {e}")

    def _save_lists(self):
        """Save whitelist and blacklist to files"""
        try:
            self._save_list_file(self.whitelist_file, self.whitelist)
            self._save_list_file(self.blacklist_file, self.blacklist)
            self.logger.debug("Saved whitelist and blacklist")
        except Exception as e:
            self.logger.error(f"Error saving lists: {e}")
            raise

    def _save_list_file(self, file_path: Path, source_dict: Dict[str, Set[str]]):
        """Save a single list file"""
        data = {
            "emails": list(source_dict["emails"]),
            "domains": list(source_dict["domains"])
        }
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _validate_email(self, email: str) -> str:
        """Validate and normalize email address"""
        try:
            validated_email = validate_email(email)
            return validated_email.email.lower()
        except EmailNotValidError as e:
            raise ValueError(f"Invalid email address '{email}': {e}")

    def _validate_domain(self, domain: str) -> str:
        """Validate and normalize domain name"""
        domain = domain.lower().strip()

        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('://', 1)[1]

        # Remove path if present
        domain = domain.split('/')[0]

        # Basic domain validation
        if not domain or '.' not in domain:
            raise ValueError(f"Invalid domain '{domain}'")

        return domain

    # Whitelist operations
    def add_to_whitelist(self, item: str, item_type: str = "auto") -> bool:
        """Add email or domain to whitelist"""
        try:
            if item_type == "auto":
                item_type = "email" if "@" in item else "domain"

            if item_type == "email":
                validated_item = self._validate_email(item)
                self.whitelist["emails"].add(validated_item)
            elif item_type == "domain":
                validated_item = self._validate_domain(item)
                self.whitelist["domains"].add(validated_item)
            else:
                raise ValueError(f"Invalid item type: {item_type}")

            self._save_lists()
            self.logger.info(f"Added {item_type} '{validated_item}' to whitelist")
            return True

        except (ValueError, Exception) as e:
            self.logger.error(f"Error adding to whitelist: {e}")
            raise

    def remove_from_whitelist(self, item: str, item_type: str = "auto") -> bool:
        """Remove email or domain from whitelist"""
        try:
            if item_type == "auto":
                item_type = "email" if "@" in item else "domain"

            if item_type == "email":
                validated_item = self._validate_email(item)
                removed = validated_item in self.whitelist["emails"]
                self.whitelist["emails"].discard(validated_item)
            elif item_type == "domain":
                validated_item = self._validate_domain(item)
                removed = validated_item in self.whitelist["domains"]
                self.whitelist["domains"].discard(validated_item)
            else:
                raise ValueError(f"Invalid item type: {item_type}")

            if removed:
                self._save_lists()
                self.logger.info(f"Removed {item_type} '{validated_item}' from whitelist")
                return True
            else:
                self.logger.warning(f"{item_type.title()} '{validated_item}' not found in whitelist")
                return False

        except (ValueError, Exception) as e:
            self.logger.error(f"Error removing from whitelist: {e}")
            raise

    def is_whitelisted(self, email: str, domain: str = None) -> Optional[str]:
        """Check if email or domain is whitelisted"""
        try:
            email = email.lower()
            if email in self.whitelist["emails"]:
                return f"Email '{email}' is whitelisted"

            if not domain:
                domain = email.split("@")[-1] if "@" in email else email

            domain = domain.lower()
            if domain in self.whitelist["domains"]:
                return f"Domain '{domain}' is whitelisted"

            return None

        except Exception as e:
            self.logger.error(f"Error checking whitelist: {e}")
            return None

    # Blacklist operations
    def add_to_blacklist(self, item: str, item_type: str = "auto") -> bool:
        """Add email or domain to blacklist"""
        try:
            if item_type == "auto":
                item_type = "email" if "@" in item else "domain"

            if item_type == "email":
                validated_item = self._validate_email(item)
                self.blacklist["emails"].add(validated_item)
            elif item_type == "domain":
                validated_item = self._validate_domain(item)
                self.blacklist["domains"].add(validated_item)
            else:
                raise ValueError(f"Invalid item type: {item_type}")

            self._save_lists()
            self.logger.info(f"Added {item_type} '{validated_item}' to blacklist")
            return True

        except (ValueError, Exception) as e:
            self.logger.error(f"Error adding to blacklist: {e}")
            raise

    def remove_from_blacklist(self, item: str, item_type: str = "auto") -> bool:
        """Remove email or domain from blacklist"""
        try:
            if item_type == "auto":
                item_type = "email" if "@" in item else "domain"

            if item_type == "email":
                validated_item = self._validate_email(item)
                removed = validated_item in self.blacklist["emails"]
                self.blacklist["emails"].discard(validated_item)
            elif item_type == "domain":
                validated_item = self._validate_domain(item)
                removed = validated_item in self.blacklist["domains"]
                self.blacklist["domains"].discard(validated_item)
            else:
                raise ValueError(f"Invalid item type: {item_type}")

            if removed:
                self._save_lists()
                self.logger.info(f"Removed {item_type} '{validated_item}' from blacklist")
                return True
            else:
                self.logger.warning(f"{item_type.title()} '{validated_item}' not found in blacklist")
                return False

        except (ValueError, Exception) as e:
            self.logger.error(f"Error removing from blacklist: {e}")
            raise

    def is_blacklisted(self, email: str, domain: str = None) -> Optional[str]:
        """Check if email or domain is blacklisted"""
        try:
            email = email.lower()
            if email in self.blacklist["emails"]:
                return f"Email '{email}' is blacklisted"

            if not domain:
                domain = email.split("@")[-1] if "@" in email else email

            domain = domain.lower()
            if domain in self.blacklist["domains"]:
                return f"Domain '{domain}' is blacklisted"

            return None

        except Exception as e:
            self.logger.error(f"Error checking blacklist: {e}")
            return None

    # List management operations
    def get_whitelist(self) -> Dict[str, List[str]]:
        """Get current whitelist contents"""
        return {
            "emails": sorted(list(self.whitelist["emails"])),
            "domains": sorted(list(self.whitelist["domains"]))
        }

    def get_blacklist(self) -> Dict[str, List[str]]:
        """Get current blacklist contents"""
        return {
            "emails": sorted(list(self.blacklist["emails"])),
            "domains": sorted(list(self.blacklist["domains"]))
        }

    def get_stats(self) -> Dict[str, int]:
        """Get statistics about lists"""
        return {
            "whitelist_emails": len(self.whitelist["emails"]),
            "whitelist_domains": len(self.whitelist["domains"]),
            "blacklist_emails": len(self.blacklist["emails"]),
            "blacklist_domains": len(self.blacklist["domains"])
        }

    def clear_whitelist(self, confirm: bool = False) -> bool:
        """Clear all whitelist entries"""
        if not confirm:
            raise ValueError("Clear operation requires explicit confirmation")

        self.whitelist["emails"].clear()
        self.whitelist["domains"].clear()
        self._save_lists()
        self.logger.warning("Cleared all whitelist entries")
        return True

    def clear_blacklist(self, confirm: bool = False) -> bool:
        """Clear all blacklist entries"""
        if not confirm:
            raise ValueError("Clear operation requires explicit confirmation")

        self.blacklist["emails"].clear()
        self.blacklist["domains"].clear()
        self._save_lists()
        self.logger.warning("Cleared all blacklist entries")
        return True

    def import_list(self, file_path: str, list_type: str, replace: bool = False):
        """Import list from file (JSON or text format)"""
        import_path = Path(file_path)
        if not import_path.exists():
            raise FileNotFoundError(f"Import file not found: {file_path}")

        if list_type not in ["whitelist", "blacklist"]:
            raise ValueError(f"Invalid list type: {list_type}")

        target_list = self.whitelist if list_type == "whitelist" else self.blacklist

        if replace:
            target_list["emails"].clear()
            target_list["domains"].clear()

        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                if import_path.suffix.lower() == '.json':
                    data = json.load(f)
                    emails = data.get("emails", [])
                    domains = data.get("domains", [])
                else:
                    # Assume text file with one item per line
                    lines = f.read().strip().split('\n')
                    emails = [line.strip() for line in lines if '@' in line]
                    domains = [line.strip() for line in lines if '@' not in line and line.strip()]

            # Add items with validation
            for email in emails:
                try:
                    validated_email = self._validate_email(email)
                    target_list["emails"].add(validated_email)
                except ValueError as e:
                    self.logger.warning(f"Skipped invalid email '{email}': {e}")

            for domain in domains:
                try:
                    validated_domain = self._validate_domain(domain)
                    target_list["domains"].add(validated_domain)
                except ValueError as e:
                    self.logger.warning(f"Skipped invalid domain '{domain}': {e}")

            self._save_lists()
            self.logger.info(f"Imported {list_type} from {file_path}")

        except Exception as e:
            self.logger.error(f"Error importing {list_type}: {e}")
            raise

    def export_list(self, file_path: str, list_type: str):
        """Export list to JSON file"""
        export_path = Path(file_path)
        export_path.parent.mkdir(parents=True, exist_ok=True)

        if list_type == "whitelist":
            data = self.get_whitelist()
        elif list_type == "blacklist":
            data = self.get_blacklist()
        else:
            raise ValueError(f"Invalid list type: {list_type}")

        try:
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            self.logger.info(f"Exported {list_type} to {file_path}")

        except Exception as e:
            self.logger.error(f"Error exporting {list_type}: {e}")
            raise