"""Email processor for spam detection workflow"""

import logging
from typing import List, Dict, Any, Optional
from ..config import ConfigManager
from .email_client import EmailClient
from ..llm import LLMClassifier
from ..ml import MLClassifier
from ..filters import ListManager
from ..stats import StatsManager


class EmailProcessor:
    """Coordinates email processing workflow"""

    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.logger = logging.getLogger(__name__)
        self.clients: Dict[str, EmailClient] = {}
        self.llm_classifier = LLMClassifier(config_manager.config)
        self.ml_classifier = MLClassifier(config_manager.config)
        self.list_manager = ListManager()
        self.feedback_processor = None  # Lazy loading to avoid circular import
        self.stats_manager = StatsManager()

    def initialize_clients(self) -> bool:
        """Initialize email clients for all configured accounts"""
        accounts = self.config.get_email_accounts()

        for account in accounts:
            name = account.get('name', 'unknown')
            try:
                client = EmailClient(
                    server=account['server'],
                    port=account['port'],
                    username=account['username'],
                    password=account['password'],
                    use_ssl=account.get('use_ssl', True)
                )

                if client.connect():
                    self.clients[name] = client
                    self.logger.info(f"Initialized client for account: {name}")
                else:
                    self.logger.error(f"Failed to connect to account: {name}")
                    return False

            except Exception as e:
                self.logger.error(f"Error initializing client for {name}: {e}")
                return False

        return len(self.clients) > 0

    def _get_feedback_processor(self):
        """Lazy initialization of feedback processor to avoid circular import"""
        if self.feedback_processor is None:
            from ..learning import FeedbackProcessor
            self.feedback_processor = FeedbackProcessor(self.config.config)
        return self.feedback_processor

    def disconnect_all(self):
        """Disconnect all email clients"""
        for name, client in self.clients.items():
            try:
                client.disconnect()
                self.logger.info(f"Disconnected client: {name}")
            except Exception as e:
                self.logger.warning(f"Error disconnecting {name}: {e}")

        self.clients.clear()

    def process_account(self, account_name: str, folder: str = "INBOX") -> Dict[str, Any]:
        """Process emails in specified account and folder"""
        if account_name not in self.clients:
            raise ValueError(f"Account {account_name} not initialized")

        client = self.clients[account_name]
        results = {
            "account": account_name,
            "folder": folder,
            "processed": 0,
            "spam_detected": 0,
            "spam_moved": 0,
            "errors": 0,
            "details": []
        }

        try:
            # Select the folder
            if not client.select_folder(folder):
                self.logger.error(f"Could not select folder {folder} for {account_name}")
                return results

            # Get unread emails (or all emails for initial scan) using safe method
            email_ids = client.get_email_ids("UNSEEN")  # Only unread emails
            self.logger.info(f"Found {len(email_ids)} unread emails in {account_name}/{folder}")

            # Process each email
            for email_id in email_ids:
                try:
                    email_data = client.fetch_email(email_id)
                    if not email_data:
                        results["errors"] += 1
                        self.logger.debug(f"Skipped invalid or deleted email {email_id}")
                        continue

                    # Process email through spam detection pipeline
                    import time
                    start_time = time.time()
                    decision = self._process_single_email(email_data)
                    processing_time = time.time() - start_time

                    results["processed"] += 1

                    # Record statistics
                    self.stats_manager.record_detection(decision, processing_time)

                    # Take action based on decision
                    if decision["action"] == "SPAM":
                        results["spam_detected"] += 1
                        if self._handle_spam_email(client, email_id, email_data, decision):
                            results["spam_moved"] += 1
                    else:
                        # Email is not spam, preserve unread status if it was originally unread
                        was_unread = email_data.get('was_unread', False)
                        if was_unread:
                            # Make sure the email stays unread
                            client.mark_email_unread(email_id)
                            self.logger.debug(f"Preserved unread status for non-spam email {email_id}")

                    # Log the decision
                    self._log_decision(email_data, decision)

                    results["details"].append({
                        "email_id": email_id,
                        "subject": email_data.get("subject", "")[:50],
                        "sender": email_data.get("sender_email", ""),
                        "action": decision["action"],
                        "reason": decision["reason"]
                    })

                except Exception as e:
                    self.logger.error(f"Error processing email {email_id}: {e}")
                    results["errors"] += 1
                    self.stats_manager.record_error("email_processing")

        except Exception as e:
            self.logger.error(f"Error processing account {account_name}: {e}")
            results["errors"] += 1

        return results

    def process_feedback(self, account_name: str = None) -> Dict[str, Any]:
        """Process user feedback from special folders"""
        if account_name and account_name not in self.clients:
            raise ValueError(f"Account {account_name} not initialized")

        accounts_to_process = [account_name] if account_name else list(self.clients.keys())
        all_results = {
            "feedback_processing": True,
            "accounts_processed": 0,
            "total_feedback": 0,
            "total_whitelist_added": 0,
            "total_blacklist_added": 0,
            "total_ml_samples": 0,
            "total_restored": 0,
            "total_errors": 0,
            "account_details": []
        }

        for account in accounts_to_process:
            try:
                client = self.clients[account]
                self.logger.info(f"Processing feedback for account: {account}")

                # Get feedback processor (lazy loading)
                feedback_processor = self._get_feedback_processor()

                # Ensure feedback folders exist
                feedback_processor.create_feedback_folders(client)

                # Process feedback
                results = feedback_processor.process_feedback_folders(client, account)

                # Accumulate results
                all_results["accounts_processed"] += 1
                all_results["total_feedback"] += results["processed_feedback"]
                all_results["total_whitelist_added"] += results["whitelist_added"]
                all_results["total_blacklist_added"] += results["blacklist_added"]
                all_results["total_ml_samples"] += results["ml_samples_collected"]
                all_results["total_restored"] += results["emails_restored"]
                all_results["total_errors"] += results["errors"]
                all_results["account_details"].append(results)

                if results["processed_feedback"] > 0:
                    self.logger.info(
                        f"Processed {results['processed_feedback']} feedback emails from {account}"
                    )

            except Exception as e:
                self.logger.error(f"Error processing feedback for account {account}: {e}")
                all_results["total_errors"] += 1
                self.stats_manager.record_error("feedback_processing")

        # Record feedback statistics
        if all_results["total_feedback"] > 0:
            self.stats_manager.record_feedback(all_results)

        return all_results

    def setup_feedback_folders(self, account_name: str = None) -> Dict[str, Any]:
        """Create feedback folders for learning"""
        if account_name and account_name not in self.clients:
            raise ValueError(f"Account {account_name} not initialized")

        accounts_to_setup = [account_name] if account_name else list(self.clients.keys())
        results = {
            "accounts_setup": 0,
            "folders_created": {},
            "errors": 0
        }

        for account in accounts_to_setup:
            try:
                client = self.clients[account]
                feedback_processor = self._get_feedback_processor()
                folder_results = feedback_processor.create_feedback_folders(client)

                results["accounts_setup"] += 1
                results["folders_created"][account] = folder_results

                # Log folder names for user reference
                folder_names = feedback_processor.get_feedback_folder_names()
                self.logger.info(f"Feedback folders for {account}:")
                for purpose, folder in folder_names.items():
                    normalized = client._normalize_folder_name(folder)
                    self.logger.info(f"  {purpose}: {normalized}")

            except Exception as e:
                self.logger.error(f"Error setting up feedback folders for {account}: {e}")
                results["errors"] += 1

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        return self.stats_manager.get_summary_stats()

    def get_daily_statistics(self, days: int = 7) -> Dict[str, Any]:
        """Get daily statistics for the last N days"""
        return self.stats_manager.get_daily_stats(days)

    def get_detection_effectiveness(self) -> Dict[str, Any]:
        """Get detection method effectiveness"""
        return self.stats_manager.get_detection_effectiveness()

    def export_statistics(self, file_path: str):
        """Export statistics to file"""
        self.stats_manager.export_stats(file_path)

    def reset_statistics(self, confirm: bool = False):
        """Reset all statistics"""
        self.stats_manager.reset_stats(confirm)

    def _process_single_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process single email through spam detection pipeline"""
        sender_email = email_data.get("sender_email", "")
        sender_domain = email_data.get("sender_domain", "")

        # TODO: Implement actual spam detection logic
        # For now, this is a placeholder that demonstrates the structure

        # Step 1: Check whitelist/blacklist (highest priority)
        whitelist_result = self._check_whitelist(sender_email, sender_domain)
        if whitelist_result:
            return {
                "action": "KEEP",
                "reason": f"WHITELIST: {whitelist_result}",
                "confidence": 1.0,
                "method": "whitelist"
            }

        blacklist_result = self._check_blacklist(sender_email, sender_domain)
        if blacklist_result:
            return {
                "action": "SPAM",
                "reason": f"BLACKLIST: {blacklist_result}",
                "confidence": 1.0,
                "method": "blacklist"
            }

        # Step 2: ML-based detection (placeholder)
        ml_result = self._ml_classify(email_data)
        if ml_result["confidence"] > self.config.get("detection.ml_confidence_threshold", 0.8):
            return ml_result

        # Step 3: LLM-based detection for uncertain cases
        if self.config.get("detection.use_llm_for_uncertain", True):
            llm_result = self._llm_classify(email_data)
            return llm_result

        # Default: keep email if uncertain
        return {
            "action": "KEEP",
            "reason": "Uncertain classification, keeping email",
            "confidence": 0.5,
            "method": "default"
        }

    def _check_whitelist(self, sender_email: str, sender_domain: str) -> Optional[str]:
        """Check if sender is in whitelist"""
        return self.list_manager.is_whitelisted(sender_email, sender_domain)

    def _check_blacklist(self, sender_email: str, sender_domain: str) -> Optional[str]:
        """Check if sender is in blacklist"""
        return self.list_manager.is_blacklisted(sender_email, sender_domain)

    def _ml_classify(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Classify email using ML model"""
        return self.ml_classifier.classify(email_data)

    def _llm_classify(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Classify email using LLM"""
        return self.llm_classifier.classify(email_data)

    def _handle_spam_email(self, client: EmailClient, email_id: str, email_data: Dict[str, Any], decision: Dict[str, Any]) -> bool:
        """Handle detected spam email according to configuration"""
        spam_folder = self.config.get("actions.move_spam_to_folder", "SPAM_AUTO")

        try:
            # Mark spam email as read before moving (spam should be read)
            client.mark_email_read(email_id)

            success = client.move_email_to_folder(email_id, spam_folder)
            if success:
                self.logger.info(f"Moved spam email {email_id} to {spam_folder}")
            return success
        except Exception as e:
            self.logger.error(f"Failed to move spam email {email_id}: {e}")
            return False

    def _log_decision(self, email_data: Dict[str, Any], decision: Dict[str, Any]):
        """Log spam detection decision"""
        # TODO: Implement detailed decision logging
        # This will be implemented with the logging module
        self.logger.info(
            f"Email decision: {decision['action']} | "
            f"From: {email_data.get('sender_email', 'unknown')} | "
            f"Subject: {email_data.get('subject', '')[:30]}... | "
            f"Reason: {decision['reason']}"
        )

    def get_account_names(self) -> List[str]:
        """Get list of configured account names"""
        return list(self.clients.keys())

    def test_connections(self) -> Dict[str, bool]:
        """Test connections to all configured email accounts"""
        results = {}
        accounts = self.config.get_email_accounts()

        for account in accounts:
            name = account.get('name', 'unknown')
            try:
                client = EmailClient(
                    server=account['server'],
                    port=account['port'],
                    username=account['username'],
                    password=account['password'],
                    use_ssl=account.get('use_ssl', True)
                )

                success = client.connect()
                if success:
                    client.disconnect()

                results[name] = success

            except Exception as e:
                self.logger.error(f"Connection test failed for {name}: {e}")
                results[name] = False

        return results