"""User feedback processing for continuous learning"""

import logging
from typing import Dict, Any, List, Optional
import json
import time
from pathlib import Path
from ..email.email_client import EmailClient
from ..filters import ListManager
from ..ml import MLClassifier
from ..stats.stats_manager import StatsManager


class FeedbackProcessor:
    """Processes user feedback from special folders to improve spam detection"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Feedback folder names
        self.feedback_folders = {
            'whitelist': 'PYANTISPAM_WHITELIST',
            'blacklist': 'PYANTISPAM_BLACKLIST',
            'not_spam': 'PYANTISPAM_NOT_SPAM',
            'is_spam': 'PYANTISPAM_IS_SPAM'
        }

        # Components
        self.list_manager = ListManager()
        self.ml_classifier = MLClassifier(config)
        self.stats_manager = StatsManager()

        # Training samples for ML retraining
        self.training_samples = []

    def process_feedback_folders(self, client: EmailClient, account_name: str) -> Dict[str, Any]:
        """Process all feedback folders for an account"""
        results = {
            "account": account_name,
            "processed_feedback": 0,
            "whitelist_added": 0,
            "blacklist_added": 0,
            "ml_samples_collected": 0,
            "emails_restored": 0,
            "errors": 0,
            "details": []
        }

        for feedback_type, folder_name in self.feedback_folders.items():
            try:
                folder_results = self._process_feedback_folder(
                    client, feedback_type, folder_name, account_name
                )

                # Accumulate results
                results["processed_feedback"] += folder_results["processed"]
                results["whitelist_added"] += folder_results.get("whitelist_added", 0)
                results["blacklist_added"] += folder_results.get("blacklist_added", 0)
                results["ml_samples_collected"] += folder_results.get("ml_samples", 0)
                results["emails_restored"] += folder_results.get("restored", 0)
                results["errors"] += folder_results.get("errors", 0)
                results["details"].extend(folder_results.get("details", []))

            except Exception as e:
                self.logger.error(f"Error processing feedback folder {folder_name}: {e}")
                results["errors"] += 1

        # Retrain ML model if we have enough new samples
        if len(self.training_samples) >= self.config.get("learning.retrain_threshold", 10):
            retrain_result = self._retrain_ml_model()
            # Record retraining in stats
            if retrain_result:
                self.stats_manager.record_ml_retrain(retrain_result)
                results["ml_retraining_performed"] = True
                results["ml_retrain_accuracy"] = retrain_result.get("accuracy", 0)

        return results

    def _compute_email_fingerprint(self, email_data: Dict[str, Any]) -> str:
        """Compute a fingerprint matching EmailProcessor logic for overrides"""
        content = f"{email_data.get('sender_email', '')}{email_data.get('subject', '')}{email_data.get('body', '')[:200]}"
        import hashlib
        return hashlib.md5(content.encode('utf-8')).hexdigest()

    def _update_llm_cache_override(self, email_data: Dict[str, Any], is_spam: bool, reason: str):
        """Persist a user feedback override into the LLM cache file"""
        try:
            cache_config = self.config.get('llm', {}).get('cache', {})
            if cache_config.get('enabled', True) is False:
                return
            cache_file_path = cache_config.get('file_path', 'data/llm_cache.json')
            cache_path = Path(cache_file_path)
            cache_path.parent.mkdir(parents=True, exist_ok=True)

            cache_data: Dict[str, Any] = {}
            if cache_path.exists():
                try:
                    with open(cache_path, 'r', encoding='utf-8') as f:
                        cache_data = json.load(f)
                except Exception:
                    cache_data = {}

            fingerprint = self._compute_email_fingerprint(email_data)
            entry = {
                "action": "SPAM" if is_spam else "KEEP",
                "reason": reason,
                "confidence": 1.0,
                "method": "user_feedback",
                "override": True,
                "timestamp": time.time()
            }
            cache_data[fingerprint] = entry

            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)

            self.logger.info("Persisted user feedback override to cache for fingerprint: %s", fingerprint[:8])
        except Exception as e:
            self.logger.error("Failed to persist user feedback override: %s", e)

    def _process_feedback_folder(self, client: EmailClient, feedback_type: str,
                                folder_name: str, account_name: str) -> Dict[str, Any]:
        """Process emails in a specific feedback folder"""
        results = {
            "folder": folder_name,
            "processed": 0,
            "whitelist_added": 0,
            "blacklist_added": 0,
            "ml_samples": 0,
            "restored": 0,
            "errors": 0,
            "details": []
        }

        try:
            # Normalize folder name for server
            normalized_folder = client._normalize_folder_name(folder_name)

            # Select feedback folder
            if not client.select_folder(normalized_folder):
                # Folder doesn't exist, create it for future use
                client._create_folder_if_not_exists(normalized_folder)
                self.logger.info(f"[account: {account_name}] Created feedback folder: {normalized_folder}")
                return results

            # Get all emails in folder
            email_ids = client.get_email_ids("ALL")
            if not email_ids:
                return results

            self.logger.info(f"[account: {account_name}] Processing {len(email_ids)} feedback emails in {normalized_folder}")

            for email_id in email_ids:
                try:
                    # Fetch email data
                    email_data = client.fetch_email(email_id)
                    if not email_data:
                        results["errors"] += 1
                        continue

                    # Process feedback based on folder type
                    feedback_result = self._process_single_feedback(
                        email_data, feedback_type, client, email_id
                    )

                    if feedback_result["success"]:
                        results["processed"] += 1
                        results[f"{feedback_result['action']}_added"] = results.get(f"{feedback_result['action']}_added", 0) + 1

                        if feedback_result.get("ml_sample"):
                            results["ml_samples"] += 1

                        if feedback_result.get("restored"):
                            results["restored"] += 1

                        results["details"].append({
                            "email_id": email_id,
                            "sender": email_data.get("sender_email", ""),
                            "subject": email_data.get("subject", "")[:50],
                            "action": feedback_result["action"],
                            "feedback_type": feedback_type,  # Add feedback type for stats
                            "item_added": feedback_result.get("item_added", ""),
                            "restored": feedback_result.get("restored", False)
                        })

                    else:
                        results["errors"] += 1

                except Exception as e:
                    self.logger.error(f"Error processing feedback email {email_id}: {e}")
                    results["errors"] += 1

        except Exception as e:
            self.logger.error(f"Error accessing feedback folder {folder_name}: {e}")
            results["errors"] += 1

        return results

    def _process_single_feedback(self, email_data: Dict[str, Any], feedback_type: str,
                               client: EmailClient, email_id: str) -> Dict[str, Any]:
        """Process a single feedback email"""
        sender_email = email_data.get("sender_email", "")
        sender_domain = email_data.get("sender_domain", "")

        result = {
            "success": False,
            "action": "",
            "item_added": "",
            "ml_sample": False,
            "restored": False
        }

        try:
            if feedback_type == "whitelist":
                # Add sender to whitelist
                # Prefer domain if it's not a major provider
                major_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']

                if sender_domain and sender_domain not in major_providers:
                    # Add domain
                    self.list_manager.add_to_whitelist(sender_domain, "domain")
                    result["item_added"] = f"domain:{sender_domain}"
                else:
                    # Add specific email
                    self.list_manager.add_to_whitelist(sender_email, "email")
                    result["item_added"] = f"email:{sender_email}"

                result["action"] = "whitelist"

                # Add as training sample (not spam)
                self.training_samples.append({
                    "email_data": email_data,
                    "is_spam": False
                })
                result["ml_sample"] = True

            elif feedback_type == "blacklist":
                # Add sender to blacklist (prefer domain for suspicious senders)
                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top']

                if any(sender_domain.endswith(tld) for tld in suspicious_tlds):
                    # Add domain for suspicious TLDs
                    self.list_manager.add_to_blacklist(sender_domain, "domain")
                    result["item_added"] = f"domain:{sender_domain}"
                else:
                    # Add specific email
                    self.list_manager.add_to_blacklist(sender_email, "email")
                    result["item_added"] = f"email:{sender_email}"

                result["action"] = "blacklist"

                # Add as training sample (spam)
                self.training_samples.append({
                    "email_data": email_data,
                    "is_spam": True
                })
                result["ml_sample"] = True

            elif feedback_type == "not_spam":
                # This was incorrectly marked as spam
                # Add as training sample (not spam)
                self.training_samples.append({
                    "email_data": email_data,
                    "is_spam": False
                })
                # Persist a KEEP override for this exact email fingerprint
                self._update_llm_cache_override(email_data, is_spam=False, reason="User feedback: not spam")
                result["action"] = "correction"
                result["item_added"] = "ml_training_ham"
                result["ml_sample"] = True

            elif feedback_type == "is_spam":
                # This should have been marked as spam
                # Add as training sample (spam)
                self.training_samples.append({
                    "email_data": email_data,
                    "is_spam": True
                })
                # Persist a SPAM override for this exact email fingerprint
                self._update_llm_cache_override(email_data, is_spam=True, reason="User feedback: is spam")
                result["action"] = "correction"
                result["item_added"] = "ml_training_spam"
                result["ml_sample"] = True

            # Route email to appropriate destination based on feedback type
            destination_folder = self._get_destination_folder(feedback_type)
            if self._move_email_to_destination(client, email_id, destination_folder):
                result["restored"] = True
                self.logger.info(f"Processed feedback and moved email {email_id} to {destination_folder}")
            else:
                self.logger.warning(f"Failed to move email {email_id} to {destination_folder}")

            result["success"] = True

        except Exception as e:
            self.logger.error(f"Error processing feedback for {email_id}: {e}")
            result["success"] = False

        return result

    def _get_destination_folder(self, feedback_type: str) -> str:
        """Get destination folder based on feedback type"""
        destinations = {
            'whitelist': 'INBOX',           # Whitelist → INBOX
            'blacklist': self.config.get("actions.move_spam_to_folder", "spam"),  # Blacklist → spam folder
            'not_spam': 'INBOX',            # Not spam → INBOX
            'is_spam': self.config.get("actions.move_spam_to_folder", "spam")     # Is spam → spam folder
        }
        return destinations.get(feedback_type, 'INBOX')

    def _move_email_to_destination(self, client: EmailClient, email_id: str, destination_folder: str) -> bool:
        """Move email to the specified destination folder"""
        try:
            # Normalize folder name for server
            normalized_folder = client._normalize_folder_name(destination_folder)

            # Create folder if it doesn't exist (for custom spam folders)
            if destination_folder != "INBOX":
                client._create_folder_if_not_exists(normalized_folder)

            # Copy email to destination
            status, data = client.imap.copy(email_id, normalized_folder)
            if status != "OK":
                self.logger.error(f"Failed to copy email {email_id} to {normalized_folder}: {data}")
                return False

            # Mark original as deleted
            client.imap.store(email_id, "+FLAGS", "\\Deleted")
            client.imap.expunge()

            return True

        except Exception as e:
            self.logger.error(f"Error moving email {email_id} to {destination_folder}: {e}")
            return False

    def _retrain_ml_model(self):
        """Retrain ML model with accumulated feedback samples"""
        try:
            self.logger.info(f"Retraining ML model with {len(self.training_samples)} new samples")

            result = self.ml_classifier.train_with_samples(self.training_samples)

            if result["success"]:
                self.logger.info(f"ML model retrained successfully. New accuracy: {result.get('accuracy', 'unknown'):.3f}")
                # Clear samples after successful training
                self.training_samples.clear()
                return result
            else:
                self.logger.error(f"ML retraining failed: {result.get('error', 'unknown')}")
                return result

        except Exception as e:
            self.logger.error(f"Error during ML retraining: {e}")
            return {"success": False, "error": str(e)}

    def create_feedback_folders(self, client: EmailClient) -> Dict[str, bool]:
        """Create all feedback folders if they don't exist"""
        results = {}

        for feedback_type, folder_name in self.feedback_folders.items():
            try:
                # Normalize folder name for server
                normalized_name = client._normalize_folder_name(folder_name)
                client._create_folder_if_not_exists(normalized_name)
                results[folder_name] = True
                self.logger.info(f"Ensured feedback folder exists: {normalized_name}")
            except Exception as e:
                self.logger.error(f"Failed to create feedback folder {folder_name}: {e}")
                results[folder_name] = False

        return results

    def get_feedback_folder_names(self) -> Dict[str, str]:
        """Get normalized feedback folder names for display"""
        return self.feedback_folders.copy()