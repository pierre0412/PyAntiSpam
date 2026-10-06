"""Email processor for spam detection workflow"""

import logging
import hashlib
import json
import os
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from ..config import ConfigManager
from .email_client import EmailClient
from ..llm import LLMClassifier
from ..ml import MLClassifier
from ..filters import ListManager
from ..stats import StatsManager
from ..rspamd import RspamdShadowClassifier
from ..embeddings import EmbeddingShadowClassifier


class EmailProcessor:
    """Coordinates email processing workflow"""

    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.logger = logging.getLogger(__name__)
        self.clients: Dict[str, EmailClient] = {}
        self.account_configs: Dict[str, Dict[str, Any]] = {}  # Store account configurations
        self.llm_classifier = LLMClassifier(config_manager)
        self.ml_classifier = MLClassifier(config_manager)
        self.rspamd_shadow = RspamdShadowClassifier(config_manager)
        self.embedding_shadow = EmbeddingShadowClassifier(config_manager)
        self.lists_shadow = bool(config_manager.get("lists.shadow", False))
        self._last_list_verdict = None
        self.list_manager = ListManager()
        self.feedback_processor = None  # Lazy loading to avoid circular import
        self.stats_manager = StatsManager()
        self.llm_training_samples = []  # Collect LLM results for ML training
        self.processed_emails_cache = {}  # Cache for processed email fingerprints
        self.processed_training_fingerprints = set()  # Track emails already used for training
        
        # Load persistent LLM cache
        self._load_cache()

    def initialize_clients(self) -> bool:
        """Initialize email clients for all configured accounts"""
        accounts = self.config.get_email_accounts()

        # Store account configurations for later use
        self.account_configs = {}

        for account in accounts:
            name = account.get('name', 'unknown')
            # Store the account config for later use (spam_folder, etc.)
            self.account_configs[name] = account

            try:
                # Get connection settings from config
                email_connection = self.config.config.get('email_connection', {})
                request_delay = email_connection.get('request_delay', 0.1)
                timeout = email_connection.get('timeout', 10)

                client = EmailClient(
                    server=account['server'],
                    port=account['port'],
                    username=account['username'],
                    password=account['password'],
                    use_ssl=account.get('use_ssl', True),
                    request_delay=request_delay,
                    timeout=timeout
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
            # Pass shared LLM cache for immediate feedback updates
            self.feedback_processor = FeedbackProcessor(self.config, self.processed_emails_cache)
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

    def process_account(self, account_name: str, folder: str = "INBOX", account_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Process emails in specified account and folder"""
        if account_name not in self.clients:
            raise ValueError(f"Account {account_name} not initialized")

        # Use stored account config if not provided
        if account_config is None:
            account_config = self.account_configs.get(account_name, {})

        client = self.clients[account_name]
        results = {
            "account": account_name,
            "folder": folder,
            "processed": 0,
            "spam_detected": 0,
            "spam_moved": 0,
            "errors": 0,
            "cleanup_deleted": 0,
            "details": []
        }

        try:
            # Perform spam folder cleanup first
            auto_delete_days = self.config.get("actions.auto_delete_after_days", 0)
            if auto_delete_days > 0:
                # Use account-specific spam folder if defined, otherwise use global setting
                spam_folder = self.config.get("actions.move_spam_to_folder", "SPAM_AUTO")
                if account_config and "spam_folder" in account_config:
                    spam_folder = account_config["spam_folder"]

                try:
                    deleted_count = client.cleanup_old_spam(spam_folder, auto_delete_days)
                    results["cleanup_deleted"] = deleted_count
                    if deleted_count > 0:
                        self.logger.info(f"[account: {account_name}] Auto-deleted {deleted_count} old emails from {spam_folder}")
                except Exception as e:
                    self.logger.warning(f"[account: {account_name}] Spam cleanup failed: {e}")

            # Select the folder
            if not client.select_folder(folder):
                self.logger.error(f"Could not select folder {folder} for {account_name}")
                return results

            # Get unread emails (or all emails for initial scan) using safe method
            email_ids = client.get_email_ids("UNSEEN")  # Only unread emails
            email_ids.reverse()
            self.logger.info(f"Found {len(email_ids)} unread emails in {account_name}/{folder}")

            # Process each email
            for email_id in email_ids:
                try:
                    email_data = client.fetch_email(email_id)
                    if not email_data:
                        results["errors"] += 1
                        self.logger.debug(f"Skipped invalid or deleted email {email_id}")
                        continue

                    # Inject account context into email data for logging
                    email_data['account_name'] = account_name

                    # Fetch raw bytes now (before any move/expunge below invalidates
                    # this email_id) if rspamd shadow mode needs them later. Only
                    # pays this extra IMAP round-trip when actually enabled.
                    raw_message_for_shadow = (
                        client.fetch_raw_message(email_id) if self.rspamd_shadow.is_enabled() else None
                    )

                    # Process email through spam detection pipeline
                    import time
                    start_time = time.time()
                    decision = self._process_single_email(email_data)
                    decision["shadow_list"] = self._last_list_verdict
                    processing_time = time.time() - start_time

                    results["processed"] += 1

                    # Get email fingerprint for stats tracking
                    email_fingerprint = self._get_email_fingerprint(email_data)

                    # Record statistics (with fingerprint to avoid double counting)
                    self.stats_manager.record_detection(decision, processing_time, email_fingerprint)

                    # Blacklist hits are backed by human feedback (3+ signalements), so
                    # they're the one kind of automatic verdict safe to teach rspamd from.
                    # Never RF/LLM verdicts. Taken before the move below invalidates the id.
                    if decision.get("method") == "blacklist" and raw_message_for_shadow:
                        self._learn_rspamd_from_blacklist(raw_message_for_shadow)

                    # Take action based on decision
                    if decision["action"] == "SPAM":
                        results["spam_detected"] += 1
                        if self._handle_spam_email(client, email_id, email_data, decision, account_config):
                            results["spam_moved"] += 1
                    else:
                        # Email is not spam, preserve unread status if it was originally unread
                        was_unread = email_data.get('was_unread', False)
                        if was_unread:
                            # Make sure the email stays unread
                            client.mark_email_unread(email_id)
                            account = email_data.get('account_name', 'unknown')
                            self.logger.debug(f"[account: {account}] Preserved unread status for non-spam email {email_id}")

                    # Log the decision
                    self._log_decision(email_data, decision)

                    # Structured record for future calibration analysis (precision at
                    # confidence threshold, not just raw accuracy). Pure observation of
                    # a decision already made and already applied — never touches mail.
                    self._log_prediction_record(email_data, decision, email_fingerprint)

                    # rspamd "mode fantôme" : scores the same email independently,
                    # logged for future calibration, never influences the decision
                    # above (already final and already applied).
                    if raw_message_for_shadow:
                        self._log_rspamd_shadow(email_data, decision, email_fingerprint, raw_message_for_shadow)

                    # Same discipline for the embedding model: observe only.
                    if self.embedding_shadow.is_enabled():
                        self._log_embedding_shadow(email_data, decision, email_fingerprint)

                    # Same discipline for the RF itself: log its raw probability for
                    # every email, even when a list/rule/LLM made the real decision,
                    # so it can be measured on the full traffic, not just the mails
                    # where it got to decide.
                    if self.ml_classifier.is_available():
                        self._log_ml_shadow(email_data, decision, email_fingerprint)

                    results["details"].append({
                        "email_id": email_id,
                        "subject": email_data.get("subject", "")[:50],
                        "sender": email_data.get("sender_email", ""),
                        "action": decision["action"],
                        "reason": decision["reason"]
                    })

                except Exception as e:
                    account = account_name
                    self.logger.error(f"[account: {account}] Error processing email {email_id}: {e}")
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
                account_config = self.account_configs.get(account, {})
                results = feedback_processor.process_feedback_folders(client, account, account_config)

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
                self.logger.info(f"[account: {account}] Feedback folders for {account}:")
                for purpose, folder in folder_names.items():
                    normalized = client._normalize_folder_name(folder)
                    self.logger.info(f"[account: {account}]   {purpose}: {normalized}")

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

        # Step 1: Check whitelist/blacklist (highest priority, unless in shadow mode:
        # then the list verdict is only recorded and the models decide)
        whitelist_result = self._check_whitelist(sender_email, sender_domain)
        blacklist_result = None if whitelist_result else self._check_blacklist(sender_email, sender_domain)
        self._last_list_verdict = "whitelist" if whitelist_result else ("blacklist" if blacklist_result else None)

        if whitelist_result and not self.lists_shadow:
            self._collect_confirmed_training_sample(email_data, is_spam=False)
            return {
                "action": "KEEP",
                "reason": f"WHITELIST: {whitelist_result}",
                "confidence": 1.0,
                "method": "whitelist"
            }

        if blacklist_result and not self.lists_shadow:
            self._collect_confirmed_training_sample(email_data, is_spam=True)
            return {
                "action": "SPAM",
                "reason": f"BLACKLIST: {blacklist_result}",
                "confidence": 1.0,
                "method": "blacklist"
            }

        # Step 2: Respect explicit user feedback overrides from cache (highest priority after lists)
        email_fingerprint = self._get_email_fingerprint(email_data)
        if email_fingerprint in self.processed_emails_cache:
            cached_result = self.processed_emails_cache[email_fingerprint].copy()
            if cached_result.get("method") == "user_feedback" or cached_result.get("override", False):
                cached_result["reason"] += " (user feedback)"
                self.logger.debug(f"Using user feedback override for email fingerprint: {email_fingerprint[:8]}...")
                return cached_result

        # Step 3: ML-based detection (placeholder)
        ml_result = self._ml_classify(email_data)
        if ml_result["confidence"] > self.config.get("detection.ml_confidence_threshold", 0.8):
            return ml_result

        # Step 4: LLM-based detection for uncertain cases
        if self.config.get("detection.use_llm_for_uncertain", True):
            # Check if we've already processed this email
            if email_fingerprint in self.processed_emails_cache:
                cached_result = self.processed_emails_cache[email_fingerprint].copy()
                cached_result["reason"] += " (cached)"
                self.logger.debug(f"Using cached LLM result for email fingerprint: {email_fingerprint[:8]}...")
                
                # Collect cached LLM result as training data for ML model
                self._collect_llm_training_sample(email_data, cached_result)
                
                return cached_result
            
            # Get LLM classification for new email
            llm_result = self._llm_classify(email_data)
            
            # Cache the result for future use
            self.processed_emails_cache[email_fingerprint] = llm_result.copy()
            
            # Save cache to disk
            self._save_cache()
            
            # Collect LLM result as training data for ML model
            self._collect_llm_training_sample(email_data, llm_result)
            
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

    def _get_email_fingerprint(self, email_data: Dict[str, Any]) -> str:
        """Generate a unique fingerprint for an email based on its content"""
        # Use sender, subject, and first 200 chars of body to create fingerprint
        content = f"{email_data.get('sender_email', '')}{email_data.get('subject', '')}{email_data.get('body', '')[:200]}"
        return hashlib.md5(content.encode('utf-8')).hexdigest()

    def _log_ml_shadow(self, email_data: Dict[str, Any], decision: Dict[str, Any], email_fingerprint: str):
        """Log the RF's raw spam probability beside the real decision (observe only).
        Same dedup discipline as the other shadow logs: peek, score, write, then mark.
        """
        index = Path("data/logs/ml_shadow_seen.json")
        try:
            action = decision.get("action")
            method = decision.get("method")
            if self._peek_logged(email_fingerprint, action, method, index):
                return

            proba = self.ml_classifier.spam_probability(email_data)
            if proba is None:
                return

            log_path = Path("data/logs/ml_shadow_log.jsonl")
            log_path.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "timestamp": time.time(),
                "fingerprint": email_fingerprint,
                "account": email_data.get("account_name", "unknown"),
                "sender_email": email_data.get("sender_email", ""),
                "real_action": action,
                "real_method": method,
                "rf_spam_proba": round(proba, 4),
            }
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._mark_logged(email_fingerprint, action, method, index)
        except Exception as e:
            self.logger.warning(f"Could not log ML shadow score (non-blocking): {e}")

    def _log_embedding_shadow(self, email_data: Dict[str, Any], decision: Dict[str, Any], email_fingerprint: str):
        """Log the embedding model's spam probability beside the real decision.
        Dedup first (peek), score, then mark only once the record is written, so a
        failed scoring attempt is retried on the next cycle.
        """
        index = Path("data/logs/embedding_shadow_seen.json")
        try:
            action = decision.get("action")
            method = decision.get("method")
            if self._peek_logged(email_fingerprint, action, method, index):
                return

            proba = self.embedding_shadow.score(email_data)
            if proba is None:
                return

            log_path = Path("data/logs/embedding_shadow_log.jsonl")
            log_path.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "timestamp": time.time(),
                "fingerprint": email_fingerprint,
                "account": email_data.get("account_name", "unknown"),
                "sender_email": email_data.get("sender_email", ""),
                "real_action": action,
                "real_method": method,
                "embedding_spam_proba": round(proba, 4),
            }
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._mark_logged(email_fingerprint, action, method, index)
        except Exception as e:
            self.logger.warning(f"Could not log embedding shadow score (non-blocking): {e}")

    def _learn_rspamd_from_blacklist(self, raw_message: bytes):
        """Best-effort: teach rspamd a blacklisted (human-confirmed) spam."""
        try:
            self.rspamd_shadow.learn_spam(raw_message)
        except Exception as e:
            self.logger.warning(f"rspamd learn from blacklist failed (non-blocking): {e}")

    def _collect_confirmed_training_sample(self, email_data: Dict[str, Any], is_spam: bool):
        """Persist a training sample for a whitelist/blacklist hit.

        These short-circuit before ML/LLM ever run (see _process_single_email),
        so without this, a sender that gets auto-blacklisted stops contributing
        any training signal at all - exactly the recurring campaigns the content
        classifier would benefit most from learning. Label is already known with
        certainty (3+ prior feedbacks), so no LLM call needed. Persisted
        immediately (not batched) so it survives even if the daemon never
        accumulates enough for a full retrain this cycle. Never affects the
        decision already returned to the caller.
        """
        try:
            sample = {"email_data": email_data.copy(), "is_spam": is_spam}
            self.ml_classifier.persist_sample(sample)
        except Exception as e:
            self.logger.warning(f"Could not persist confirmed training sample (non-blocking): {e}")

    def _collect_llm_training_sample(self, email_data: Dict[str, Any], llm_result: Dict[str, Any]):
        """Collect LLM classification result as training data for ML model"""
        try:
            # Only collect high-confidence LLM results
            if llm_result.get("confidence", 0) >= 0.7:
                # Check if we've already collected a training sample for this email
                email_fingerprint = self._get_email_fingerprint(email_data)
                if email_fingerprint in self.processed_training_fingerprints:
                    return  # Skip duplicate training sample
                
                is_spam = llm_result.get("action") == "SPAM"
                
                # Create training sample in the format expected by MLClassifier
                training_sample = {
                    "email_data": email_data.copy(),
                    "is_spam": is_spam
                }
                
                self.llm_training_samples.append(training_sample)
                self.processed_training_fingerprints.add(email_fingerprint)
                self.logger.debug(f"Collected LLM training sample: spam={is_spam}, confidence={llm_result.get('confidence', 0):.2f}")
                
                # Retrain ML model periodically when we have enough samples
                if len(self.llm_training_samples) >= 10:
                    self._retrain_ml_with_llm_samples()
                    
        except Exception as e:
            self.logger.error(f"Error collecting LLM training sample: {e}")

    def _retrain_ml_with_llm_samples(self):
        """Retrain ML model with collected LLM samples"""
        try:
            self.logger.warning(f"🤖 DÉCLENCHEMENT RÉENTRAÎNEMENT ML avec {len(self.llm_training_samples)} échantillons LLM")

            result = self.ml_classifier.train_with_samples(self.llm_training_samples)

            if result["success"]:
                accuracy = result.get('accuracy', 0)
                self.logger.warning(f"✅ RÉENTRAÎNEMENT ML TERMINÉ avec succès ! Nouvelle précision: {accuracy:.3f}")
                # Record retraining stats
                self.stats_manager.record_ml_retrain(result)
                # Clear samples after successful training
                self.llm_training_samples.clear()
            else:
                error = result.get('error', 'unknown')
                self.logger.error(f"❌ ÉCHEC du réentraînement ML avec échantillons LLM: {error}")

        except Exception as e:
            self.logger.error(f"❌ ERREUR durant le réentraînement ML avec échantillons LLM: {e}")

    def _handle_spam_email(self, client: EmailClient, email_id: str, email_data: Dict[str, Any], decision: Dict[str, Any], account_config: Dict[str, Any] = None) -> bool:
        """Handle detected spam email according to configuration"""
        # Use account-specific spam folder if defined, otherwise use global setting
        spam_folder = account_config.get("spam_folder", self.config.get("actions.move_spam_to_folder", "SPAM_AUTO"))
        if account_config and "spam_folder" in account_config:
            spam_folder = account_config["spam_folder"]

        try:
            # Mark spam email as read before moving (spam should be read)
            client.mark_email_read(email_id)

            success = client.move_email_to_folder(email_id, spam_folder)
            if success:
                account = email_data.get('account_name', 'unknown')
                self.logger.info(f"[account: {account}] Moved spam email {email_id} to {spam_folder}")
            return success
        except Exception as e:
            account = email_data.get('account_name', 'unknown')
            self.logger.error(f"[account: {account}] Failed to move spam email {email_id}: {e}")
            return False

    def _log_decision(self, email_data: Dict[str, Any], decision: Dict[str, Any]):
        """Log spam detection decision"""
        account = email_data.get('account_name', 'unknown')
        self.logger.info(
            f"[account: {account}] Email decision: {decision['action']} | "
            f"From: {email_data.get('sender_email', 'unknown')} | "
            f"Subject: {email_data.get('subject', '')[:30]}... | "
            f"Reason: {decision['reason']}"
        )

    def _peek_logged(self, fingerprint: str, action: str, method: str, index_path: Path) -> bool:
        """Read-only check: was this exact (fingerprint, action, method) already
        marked as logged? Never writes - see _mark_logged for that.
        """
        try:
            if not index_path.exists():
                return False
            with open(index_path, 'r', encoding='utf-8') as f:
                seen: Dict[str, List[str]] = json.load(f)
            return seen.get(fingerprint) == [action, method]
        except Exception as e:
            self.logger.warning(f"Could not read dedup index {index_path} (treating as not seen): {e}")
            return False

    def _mark_logged(self, fingerprint: str, action: str, method: str, index_path: Path):
        """Record that (fingerprint, action, method) has been successfully logged."""
        try:
            seen: Dict[str, List[str]] = {}
            if index_path.exists():
                with open(index_path, 'r', encoding='utf-8') as f:
                    seen = json.load(f)
            seen[fingerprint] = [action, method]
            index_path.parent.mkdir(parents=True, exist_ok=True)
            with open(index_path, 'w', encoding='utf-8') as f:
                json.dump(seen, f, ensure_ascii=False)
        except Exception as e:
            self.logger.warning(f"Could not update dedup index {index_path} (non-blocking): {e}")

    def _already_logged(
        self, fingerprint: str, action: str, method: str,
        index_path: Path = Path("data/logs/prediction_log_seen.json"),
    ) -> bool:
        """Check (and unconditionally mark) the small fingerprint->last-decision
        index. Used where logging itself can't fail (local prediction_log write) -
        for anything that can fail independently of the dedup check (e.g. an
        rspamd network call), use _peek_logged + _mark_logged instead so a
        failed attempt can still be retried next cycle instead of being
        permanently marked as "done".

        EmailProcessor is recreated every daemon cycle (see cli.py daemon loop),
        so an in-memory dedup set wouldn't survive between cycles - a still-unread
        email gets fully reprocessed every cycle by design. Without this, the
        prediction log fills with thousands of identical repeats of the same
        handful of unread emails instead of real signal. We persist the small
        index (one entry per email ever seen, not per cycle) instead.

        index_path lets independent logs (prediction_log, rspamd shadow log)
        keep separate dedup state - sharing one index would make the second
        logger see every fingerprint as "already logged" by the first.
        """
        try:
            seen: Dict[str, List[str]] = {}
            if index_path.exists():
                with open(index_path, 'r', encoding='utf-8') as f:
                    seen = json.load(f)

            current = [action, method]
            if seen.get(fingerprint) == current:
                return True

            seen[fingerprint] = current
            index_path.parent.mkdir(parents=True, exist_ok=True)
            with open(index_path, 'w', encoding='utf-8') as f:
                json.dump(seen, f, ensure_ascii=False)
            return False
        except Exception as e:
            self.logger.warning(f"Could not check prediction dedup index (logging anyway): {e}")
            return False

    def _log_prediction_record(self, email_data: Dict[str, Any], decision: Dict[str, Any], email_fingerprint: str):
        """Append a structured prediction record for future calibration analysis.

        Separate from _log_decision (human-readable log): this is JSONL, one line
        per email, meant to be joined later against real feedback (blacklist/
        whitelist/is_spam/not_spam) to measure precision at confidence threshold,
        not just raw accuracy. Append-only by design - never read-modify-write
        the whole file. Skips writing when the exact same decision for this email
        was already logged (see _already_logged) - only new or changed verdicts
        are worth keeping for calibration analysis.
        """
        try:
            action = decision.get("action")
            method = decision.get("method")
            if self._already_logged(email_fingerprint, action, method):
                return

            log_path = Path("data/logs/prediction_log.jsonl")
            log_path.parent.mkdir(parents=True, exist_ok=True)

            record = {
                "timestamp": time.time(),
                "fingerprint": email_fingerprint,
                "account": email_data.get("account_name", "unknown"),
                "sender_email": email_data.get("sender_email", ""),
                "sender_domain": email_data.get("sender_domain", ""),
                "subject": email_data.get("subject", "")[:100],
                "action": action,
                "confidence": decision.get("confidence"),
                "method": method,
                "shadow_list": decision.get("shadow_list"),
            }

            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as e:
            self.logger.warning(f"Could not write prediction record (non-blocking): {e}")

    def _log_rspamd_shadow(
        self, email_data: Dict[str, Any], decision: Dict[str, Any],
        email_fingerprint: str, raw_message: bytes,
    ):
        """rspamd "mode fantôme" (roadmap étape 2): score this email with rspamd
        purely for observation, side by side with the real decision, to later
        calibrate how much to trust/weight rspamd before ever wiring it into
        the real pipeline. Called only after the real decision is already
        final and already applied - a slow/down/wrong rspamd call here can
        never change what happened to the mail.

        Own dedup index (separate from _log_prediction_record's) so a still-
        unread email doesn't get re-sent to rspamd every daemon cycle - each
        call costs a real network round-trip (~1-1.5s), unlike the local-only
        prediction record.
        """
        shadow_index = Path("data/logs/rspamd_shadow_seen.json")
        try:
            action = decision.get("action")
            method = decision.get("method")
            # Read-only peek here - do NOT mark as seen yet. If the rspamd call
            # below fails, this email must still look "unseen" next cycle so it
            # gets retried, instead of being silently skipped forever.
            if self._peek_logged(email_fingerprint, action, method, shadow_index):
                return

            verdict = self.rspamd_shadow.check(raw_message)
            if verdict is None:
                return  # rspamd unavailable/failed this time - retried next cycle

            log_path = Path("data/logs/rspamd_shadow_log.jsonl")
            log_path.parent.mkdir(parents=True, exist_ok=True)

            record = {
                "timestamp": time.time(),
                "fingerprint": email_fingerprint,
                "account": email_data.get("account_name", "unknown"),
                "sender_email": email_data.get("sender_email", ""),
                "real_action": action,
                "real_method": method,
                "real_confidence": decision.get("confidence"),
                "rspamd_score": verdict.get("score"),
                "rspamd_action": verdict.get("action"),
                "rspamd_top_symbols": verdict.get("top_symbols"),
            }

            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

            # Only mark as seen now that the verdict was actually captured.
            self._mark_logged(email_fingerprint, action, method, shadow_index)
        except Exception as e:
            self.logger.warning(f"Could not log rspamd shadow verdict (non-blocking): {e}")

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
                # Get connection settings from config
                email_connection = self.config.config.get('email_connection', {})
                request_delay = email_connection.get('request_delay', 0.1)
                timeout = email_connection.get('timeout', 10)

                client = EmailClient(
                    server=account['server'],
                    port=account['port'],
                    username=account['username'],
                    password=account['password'],
                    use_ssl=account.get('use_ssl', True),
                    request_delay=request_delay,
                    timeout=timeout
                )

                success = client.connect()
                if success:
                    client.disconnect()

                results[name] = success

            except Exception as e:
                self.logger.error(f"Connection test failed for {name}: {e}")
                results[name] = False

        return results

    def _load_cache(self):
        """Load LLM cache from disk if enabled"""
        try:
            # Check if cache is enabled in config
            cache_config = self.config.config.get('llm', {}).get('cache', {})
            if not cache_config.get('enabled', True):
                self.logger.debug("LLM cache is disabled in configuration")
                return
            
            cache_file_path = cache_config.get('file_path', 'data/llm_cache.json')
            
            # Create data directory if it doesn't exist
            cache_path = Path(cache_file_path)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            
            if cache_path.exists():
                with open(cache_path, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                
                # Load cache entries, optionally filtering by age
                max_age_days = cache_config.get('max_age_days', 30)
                current_time = time.time()
                loaded_entries = 0
                expired_entries = 0
                
                for email_fingerprint, cache_entry in cache_data.items():
                    # Check if entry has timestamp and is not too old
                    if max_age_days > 0 and 'timestamp' in cache_entry:
                        entry_age_days = (current_time - cache_entry['timestamp']) / (24 * 3600)
                        if entry_age_days > max_age_days:
                            expired_entries += 1
                            continue
                    
                    # Load the LLM result (remove timestamp for compatibility)
                    llm_result = cache_entry.copy()
                    llm_result.pop('timestamp', None)
                    self.processed_emails_cache[email_fingerprint] = llm_result
                    loaded_entries += 1
                
                self.logger.info(f"Loaded {loaded_entries} LLM cache entries from {cache_file_path}")
                if expired_entries > 0:
                    self.logger.info(f"Skipped {expired_entries} expired cache entries")
            else:
                self.logger.debug(f"No LLM cache file found at {cache_file_path}")
                
        except Exception as e:
            self.logger.error(f"Error loading LLM cache: {e}")
            # Continue with empty cache on error
            self.processed_emails_cache = {}

    def _save_cache(self):
        """Save LLM cache to disk if enabled"""
        try:
            # Check if cache is enabled in config
            cache_config = self.config.config.get('llm', {}).get('cache', {})
            if not cache_config.get('enabled', True):
                return
            
            cache_file_path = cache_config.get('file_path', 'data/llm_cache.json')
            
            # Create data directory if it doesn't exist
            cache_path = Path(cache_file_path)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Prepare cache data with timestamps
            current_time = time.time()
            cache_data = {}
            
            for email_fingerprint, llm_result in self.processed_emails_cache.items():
                cache_entry = llm_result.copy()
                cache_entry['timestamp'] = current_time
                cache_data[email_fingerprint] = cache_entry
            
            # Write cache to file
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
            
            self.logger.debug(f"Saved {len(cache_data)} LLM cache entries to {cache_file_path}")
            
        except Exception as e:
            self.logger.error(f"Error saving LLM cache: {e}")