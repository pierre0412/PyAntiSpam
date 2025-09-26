"""Statistics manager for tracking spam detection and learning metrics"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from collections import defaultdict


class StatsManager:
    """Manages statistics for spam detection and learning"""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)

        self.stats_file = self.data_dir / "spam_stats.json"
        self.processed_emails_file = self.data_dir / "processed_emails.json"
        self.logger = logging.getLogger(__name__)

        # Track processed emails to avoid double counting
        self.processed_emails = set()

        # Initialize stats structure
        self.stats = {
            "detection": {
                "total_emails_processed": 0,
                "spam_detected": 0,
                "ham_detected": 0,
                "detection_methods": {
                    "whitelist": 0,
                    "blacklist": 0,
                    "ml_random_forest": 0,
                    "llm_openai": 0,
                    "llm_anthropic": 0,
                    "default": 0
                },
                "confidence_distribution": {
                    "high": 0,    # >= 0.8
                    "medium": 0,  # 0.5-0.8
                    "low": 0      # < 0.5
                }
            },
            "learning": {
                "total_feedback": 0,
                "whitelist_additions": 0,
                "blacklist_additions": 0,
                "ml_training_samples": 0,
                "ml_retraining_count": 0,
                "last_retrain_date": None,
                "feedback_by_type": {
                    "whitelist": 0,
                    "blacklist": 0,
                    "not_spam": 0,
                    "is_spam": 0
                }
            },
            "performance": {
                "processing_times": [],
                "avg_processing_time": 0.0,
                "errors_count": 0,
                "last_error_date": None
            },
            "daily_stats": {},  # Date -> stats for that day
            "last_updated": None,
            "version": "1.0"
        }

        self._load_stats()
        self._load_processed_emails()

    def _load_stats(self):
        """Load statistics from file"""
        try:
            if self.stats_file.exists():
                with open(self.stats_file, 'r', encoding='utf-8') as f:
                    loaded_stats = json.load(f)
                    # Merge with default structure to handle version upgrades
                    self._merge_stats(loaded_stats)
                self.logger.debug("Loaded statistics from file")
            else:
                self.logger.info("No existing stats file, starting fresh")
        except Exception as e:
            self.logger.error(f"Error loading stats: {e}")

    def _merge_stats(self, loaded_stats: Dict[str, Any]):
        """Merge loaded stats with current structure"""
        def deep_merge(base: Dict, update: Dict):
            for key, value in update.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    deep_merge(base[key], value)
                else:
                    base[key] = value

        deep_merge(self.stats, loaded_stats)

    def _load_processed_emails(self):
        """Load processed emails tracking from file"""
        try:
            if self.processed_emails_file.exists():
                with open(self.processed_emails_file, 'r', encoding='utf-8') as f:
                    processed_list = json.load(f)
                    self.processed_emails = set(processed_list)
                self.logger.debug(f"Loaded {len(self.processed_emails)} processed email fingerprints")
            else:
                self.logger.debug("No processed emails file found, starting fresh")
        except Exception as e:
            self.logger.error(f"Error loading processed emails: {e}")
            self.processed_emails = set()

    def _save_processed_emails(self):
        """Save processed emails tracking to file"""
        try:
            # Only keep recent processed emails to avoid file growing too large
            # Keep emails from last 30 days worth of processing
            max_entries = 10000
            if len(self.processed_emails) > max_entries:
                # Keep the most recent entries (this is a simple approach)
                processed_list = list(self.processed_emails)
                self.processed_emails = set(processed_list[-max_entries:])

            with open(self.processed_emails_file, 'w', encoding='utf-8') as f:
                json.dump(list(self.processed_emails), f, ensure_ascii=False)
            self.logger.debug(f"Saved {len(self.processed_emails)} processed email fingerprints")
        except Exception as e:
            self.logger.error(f"Error saving processed emails: {e}")

    def _save_stats(self):
        """Save statistics to file"""
        try:
            self.stats["last_updated"] = datetime.now().isoformat()
            with open(self.stats_file, 'w', encoding='utf-8') as f:
                json.dump(self.stats, f, indent=2, ensure_ascii=False)
            self.logger.debug("Saved statistics to file")
        except Exception as e:
            self.logger.error(f"Error saving stats: {e}")

    def _get_today_key(self) -> str:
        """Get today's date key for daily stats"""
        return datetime.now().strftime("%Y-%m-%d")

    def _ensure_daily_stats(self, date_key: str):
        """Ensure daily stats structure exists"""
        if date_key not in self.stats["daily_stats"]:
            self.stats["daily_stats"][date_key] = {
                "emails_processed": 0,
                "spam_detected": 0,
                "ham_detected": 0,
                "feedback_processed": 0,
                "methods_used": {},
                "errors": 0
            }

    def record_detection(self, decision: Dict[str, Any], processing_time: float = 0.0, email_fingerprint: str = None):
        """Record a spam detection decision"""
        try:
            # Check if this email was already processed (avoid double counting)
            if email_fingerprint and email_fingerprint in self.processed_emails:
                self.logger.debug(f"Skipping stats for already processed email: {email_fingerprint[:8]}...")
                return

            action = decision.get("action", "KEEP")
            method = decision.get("method", "unknown")
            confidence = decision.get("confidence", 0.5)

            today = self._get_today_key()
            self._ensure_daily_stats(today)

            # Update totals
            self.stats["detection"]["total_emails_processed"] += 1
            self.stats["daily_stats"][today]["emails_processed"] += 1

            # Record spam vs ham
            if action == "SPAM":
                self.stats["detection"]["spam_detected"] += 1
                self.stats["daily_stats"][today]["spam_detected"] += 1
            else:
                self.stats["detection"]["ham_detected"] += 1
                self.stats["daily_stats"][today]["ham_detected"] += 1

            # Record detection method
            if method in self.stats["detection"]["detection_methods"]:
                self.stats["detection"]["detection_methods"][method] += 1
                # Ensure methods_used is a proper dict and initialize if needed
                if method not in self.stats["daily_stats"][today]["methods_used"]:
                    self.stats["daily_stats"][today]["methods_used"][method] = 0
                self.stats["daily_stats"][today]["methods_used"][method] += 1

            # Record confidence distribution
            if confidence >= 0.8:
                self.stats["detection"]["confidence_distribution"]["high"] += 1
            elif confidence >= 0.5:
                self.stats["detection"]["confidence_distribution"]["medium"] += 1
            else:
                self.stats["detection"]["confidence_distribution"]["low"] += 1

            # Record processing time
            if processing_time > 0:
                self.stats["performance"]["processing_times"].append(processing_time)
                # Keep only last 1000 times to avoid memory issues
                if len(self.stats["performance"]["processing_times"]) > 1000:
                    self.stats["performance"]["processing_times"] = \
                        self.stats["performance"]["processing_times"][-1000:]

                # Update average
                times = self.stats["performance"]["processing_times"]
                self.stats["performance"]["avg_processing_time"] = sum(times) / len(times)

            # Mark email as processed to avoid future double counting
            if email_fingerprint:
                self.processed_emails.add(email_fingerprint)
                self._save_processed_emails()

            self._save_stats()

        except Exception as e:
            self.logger.error(f"Error recording detection stats: {e}")
            self.logger.error(f"Decision data: {decision}")
            self.logger.error(f"Method: {method}, Action: {action}, Confidence: {confidence}")

    def record_feedback(self, feedback_results: Dict[str, Any]):
        """Record feedback learning results"""
        try:
            today = self._get_today_key()
            self._ensure_daily_stats(today)

            # Update feedback totals
            total_feedback = feedback_results.get("total_feedback", 0)
            self.stats["learning"]["total_feedback"] += total_feedback
            self.stats["daily_stats"][today]["feedback_processed"] += total_feedback

            # Update list additions
            whitelist_added = feedback_results.get("total_whitelist_added", 0)
            blacklist_added = feedback_results.get("total_blacklist_added", 0)
            ml_samples = feedback_results.get("total_ml_samples", 0)

            self.stats["learning"]["whitelist_additions"] += whitelist_added
            self.stats["learning"]["blacklist_additions"] += blacklist_added
            self.stats["learning"]["ml_training_samples"] += ml_samples

            # Record feedback by type from details
            for account_detail in feedback_results.get("account_details", []):
                for detail in account_detail.get("details", []):
                    feedback_type = detail.get("feedback_type", "unknown")
                    if feedback_type in self.stats["learning"]["feedback_by_type"]:
                        self.stats["learning"]["feedback_by_type"][feedback_type] += 1

            self._save_stats()

        except Exception as e:
            self.logger.error(f"Error recording feedback stats: {e}")

    def record_ml_retrain(self, retrain_results: Dict[str, Any]):
        """Record ML model retraining"""
        try:
            if retrain_results.get("success", False):
                self.stats["learning"]["ml_retraining_count"] += 1
                self.stats["learning"]["last_retrain_date"] = datetime.now().isoformat()
                accuracy = retrain_results.get("accuracy", 0)

                # Log important retraining event
                self.logger.warning(f"📊 STATS: Réentraînement ML #{self.stats['learning']['ml_retraining_count']} enregistré avec succès (précision: {accuracy:.3f})")

            self._save_stats()

        except Exception as e:
            self.logger.error(f"Error recording retrain stats: {e}")

    def record_error(self, error_type: str = "general"):
        """Record an error occurrence"""
        try:
            today = self._get_today_key()
            self._ensure_daily_stats(today)

            self.stats["performance"]["errors_count"] += 1
            self.stats["performance"]["last_error_date"] = datetime.now().isoformat()
            self.stats["daily_stats"][today]["errors"] += 1

            self._save_stats()

        except Exception as e:
            self.logger.error(f"Error recording error stats: {e}")

    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics"""
        detection = self.stats["detection"]
        learning = self.stats["learning"]
        performance = self.stats["performance"]

        total_emails = detection["total_emails_processed"]
        spam_rate = (detection["spam_detected"] / total_emails * 100) if total_emails > 0 else 0

        return {
            "overview": {
                "total_emails_processed": total_emails,
                "spam_detected": detection["spam_detected"],
                "ham_detected": detection["ham_detected"],
                "spam_detection_rate": round(spam_rate, 2)
            },
            "detection_methods": detection["detection_methods"],
            "confidence_distribution": detection["confidence_distribution"],
            "learning": {
                "total_feedback": learning["total_feedback"],
                "whitelist_additions": learning["whitelist_additions"],
                "blacklist_additions": learning["blacklist_additions"],
                "ml_training_samples": learning["ml_training_samples"],
                "ml_retraining_count": learning["ml_retraining_count"],
                "feedback_by_type": learning["feedback_by_type"]
            },
            "performance": {
                "avg_processing_time": round(performance["avg_processing_time"], 3),
                "errors_count": performance["errors_count"],
                "last_error_date": performance["last_error_date"]
            }
        }

    def get_daily_stats(self, days: int = 7) -> Dict[str, Any]:
        """Get daily statistics for the last N days"""
        daily_stats = {}

        for i in range(days):
            date = datetime.now() - timedelta(days=i)
            date_key = date.strftime("%Y-%m-%d")

            if date_key in self.stats["daily_stats"]:
                daily_stats[date_key] = self.stats["daily_stats"][date_key].copy()
                # Convert defaultdict to regular dict for JSON serialization
                if "methods_used" in daily_stats[date_key]:
                    daily_stats[date_key]["methods_used"] = dict(daily_stats[date_key]["methods_used"])
            else:
                daily_stats[date_key] = {
                    "emails_processed": 0,
                    "spam_detected": 0,
                    "ham_detected": 0,
                    "feedback_processed": 0,
                    "methods_used": {},
                    "errors": 0
                }

        return daily_stats

    def get_detection_effectiveness(self) -> Dict[str, Any]:
        """Get detection method effectiveness"""
        methods = self.stats["detection"]["detection_methods"]
        total = sum(methods.values())

        if total == 0:
            return {"error": "No detection data available"}

        effectiveness = {}
        for method, count in methods.items():
            percentage = (count / total) * 100
            effectiveness[method] = {
                "count": count,
                "percentage": round(percentage, 2)
            }

        return effectiveness

    def export_stats(self, file_path: str):
        """Export statistics to file"""
        try:
            export_data = {
                "exported_at": datetime.now().isoformat(),
                "summary": self.get_summary_stats(),
                "daily_stats": self.get_daily_stats(30),  # Last 30 days
                "effectiveness": self.get_detection_effectiveness(),
                "raw_stats": self.stats
            }

            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)

            self.logger.info(f"Statistics exported to {file_path}")

        except Exception as e:
            self.logger.error(f"Error exporting stats: {e}")
            raise

    def reset_stats(self, confirm: bool = False):
        """Reset all statistics (requires confirmation)"""
        if not confirm:
            raise ValueError("Reset operation requires explicit confirmation")

        # Keep the structure but reset values
        self.stats["detection"]["total_emails_processed"] = 0
        self.stats["detection"]["spam_detected"] = 0
        self.stats["detection"]["ham_detected"] = 0
        for method in self.stats["detection"]["detection_methods"]:
            self.stats["detection"]["detection_methods"][method] = 0
        for level in self.stats["detection"]["confidence_distribution"]:
            self.stats["detection"]["confidence_distribution"][level] = 0

        self.stats["learning"]["total_feedback"] = 0
        self.stats["learning"]["whitelist_additions"] = 0
        self.stats["learning"]["blacklist_additions"] = 0
        self.stats["learning"]["ml_training_samples"] = 0
        self.stats["learning"]["ml_retraining_count"] = 0
        self.stats["learning"]["last_retrain_date"] = None
        for feedback_type in self.stats["learning"]["feedback_by_type"]:
            self.stats["learning"]["feedback_by_type"][feedback_type] = 0

        self.stats["performance"]["processing_times"] = []
        self.stats["performance"]["avg_processing_time"] = 0.0
        self.stats["performance"]["errors_count"] = 0
        self.stats["performance"]["last_error_date"] = None

        self.stats["daily_stats"] = {}

        # Also reset processed emails tracking
        self.processed_emails = set()
        self._save_processed_emails()

        self._save_stats()
        self.logger.warning("All statistics have been reset")