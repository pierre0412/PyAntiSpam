"""ML-based spam classification using scikit-learn"""

import logging
import pickle
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    from sklearn.preprocessing import StandardScaler
    sklearn_available = True
except ImportError:
    sklearn_available = False

from .feature_extractor import FeatureExtractor


class MLClassifier:
    """ML-based spam classifier using Random Forest"""

    def __init__(self, config: Dict[str, Any], data_dir: str = "data"):
        self.config = config
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)

        # Initialize feature extractor
        self.feature_extractor = FeatureExtractor()

        # Model components
        self.model = None
        self.scaler = StandardScaler() if sklearn_available else None
        self.feature_names = self.feature_extractor.get_feature_names()
        self.model_trained = False

        # File paths
        self.model_file = self.data_dir / "spam_model.pkl"
        self.scaler_file = self.data_dir / "feature_scaler.pkl"
        self.training_data_file = self.data_dir / "training_data.json"
        self.feature_names_file = self.data_dir / "feature_names.json"

        if not sklearn_available:
            self.logger.warning("scikit-learn not available. ML classification disabled.")
        else:
            self._load_model()

    def is_available(self) -> bool:
        """Check if ML classification is available"""
        return sklearn_available and self.model_trained

    def classify(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Classify email as spam or not using ML model"""
        if not self.is_available():
            return {
                "action": "KEEP",
                "reason": "ML model not available or trained",
                "confidence": 0.5,
                "method": "ml_unavailable"
            }

        try:
            # Extract features
            features = self.feature_extractor.extract_features(email_data)

            # Convert to feature vector
            feature_vector = self._features_to_vector(features)

            # Scale features
            try:
                feature_vector_scaled = self.scaler.transform([feature_vector])
            except Exception as shape_err:
                # Handle feature size mismatch by reinitializing the model with current features
                self.logger.warning(f"Scaler transform failed (likely feature mismatch): {shape_err}. Attempting auto-reinit.")
                reinit = self.initialize_default_model()
                if reinit.get("success"):
                    try:
                        feature_vector = self._features_to_vector(self.feature_extractor.extract_features(email_data))
                        feature_vector_scaled = self.scaler.transform([feature_vector])
                    except Exception as e2:
                        raise e2
                else:
                    raise shape_err

            # Get prediction and probability
            prediction = self.model.predict(feature_vector_scaled)[0]
            probabilities = self.model.predict_proba(feature_vector_scaled)[0]

            # Get confidence (probability of predicted class)
            # Handle cases where model was trained with only one class
            if len(probabilities) == 1:
                # Only one class available, use the single probability
                confidence = probabilities[0]
            else:
                # Normal case with both classes
                confidence = probabilities[1] if prediction == 1 else probabilities[0]

            # Determine action
            is_spam = prediction == 1

            # Check for marketing-specific classification if enabled
            if not is_spam and self.config.get("detection.classify_marketing_as_spam", True):
                marketing_score = self._calculate_marketing_score(features)
                marketing_threshold = self.config.get("detection.marketing_confidence_threshold", 0.6)

                if marketing_score >= marketing_threshold:
                    return {
                        "action": "SPAM",
                        "reason": f"ML: Marketing content detected (score: {marketing_score:.2f})",
                        "confidence": float(marketing_score),
                        "method": "ml_marketing"
                    }

            return {
                "action": "SPAM" if is_spam else "KEEP",
                "reason": f"ML: {'Spam' if is_spam else 'Ham'} (conf: {confidence:.2f})",
                "confidence": float(confidence),
                "method": "ml_random_forest"
            }

        except Exception as e:
            self.logger.error(f"ML classification error: {e}")
            return {
                "action": "KEEP",
                "reason": f"ML error: {str(e)[:50]}",
                "confidence": 0.5,
                "method": "ml_error"
            }

    def _features_to_vector(self, features: Dict[str, float]) -> np.ndarray:
        """Convert feature dictionary to numpy vector"""
        vector = []
        for feature_name in self.feature_names:
            vector.append(features.get(feature_name, 0.0))
        return np.array(vector)

    def _calculate_sample_weight(self, sample: Dict[str, Any], features: Dict[str, float]) -> float:
        """
        Calculate sample weight based on source and sender history.

        Weight strategy:
        - Default samples: 1.0 (baseline)
        - User feedback: 3.0 (learn more from corrections)
        - Recurring sender feedback: 5.0 (learn heavily from patterns)
        """
        base_weight = 1.0

        # Check if this is user feedback
        source = sample.get('source', 'default')
        if source == 'user_feedback':
            base_weight = 3.0

        # Boost weight for recurring senders (strong pattern signal)
        sender_total_feedbacks = features.get('sender_total_feedbacks', 0)
        is_recurring = features.get('sender_is_recurring_spammer', 0) == 1.0 or \
                      features.get('sender_is_recurring_ham', 0) == 1.0

        if is_recurring or sender_total_feedbacks >= 3:
            # This is a recurring sender with established pattern
            return 5.0
        elif sender_total_feedbacks >= 2:
            # Sender has some feedback history
            return base_weight * 1.5

        return base_weight

    def train_with_samples(self, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train the model with provided samples"""
        if not sklearn_available:
            return {"success": False, "error": "scikit-learn not available"}

        if len(samples) < 10:
            return {"success": False, "error": "Need at least 10 samples for training"}

        try:
            # Extract features, labels, and weights
            X, y, sample_weights = [], [], []

            for sample in samples:
                features = self.feature_extractor.extract_features(sample['email_data'])
                feature_vector = self._features_to_vector(features)
                X.append(feature_vector)
                y.append(1 if sample['is_spam'] else 0)

                # Calculate sample weight based on source and sender history
                weight = self._calculate_sample_weight(sample, features)
                sample_weights.append(weight)

            X = np.array(X)
            y = np.array(y)
            sample_weights = np.array(sample_weights)

            # Split data (including sample weights)
            if len(X) >= 20:
                X_train, X_test, y_train, y_test, weights_train, weights_test = train_test_split(
                    X, y, sample_weights, test_size=0.2, random_state=42, stratify=y
                )
            else:
                X_train, X_test, y_train, y_test = X, X, y, y
                weights_train, weights_test = sample_weights, sample_weights

            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)

            # Train model with sample weights
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight='balanced'
            )

            self.model.fit(X_train_scaled, y_train, sample_weight=weights_train)

            # Evaluate
            y_pred = self.model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)

            # Save model
            self._save_model()
            self.model_trained = True

            # Save training data for future use
            self._save_training_data(samples)

            # Calculate weight statistics
            weight_stats = {
                "min": float(np.min(sample_weights)),
                "max": float(np.max(sample_weights)),
                "mean": float(np.mean(sample_weights)),
                "total": float(np.sum(sample_weights))
            }

            self.logger.info(f"Model trained successfully. Accuracy: {accuracy:.3f}")
            self.logger.info(f"Sample weights - min: {weight_stats['min']:.1f}, max: {weight_stats['max']:.1f}, mean: {weight_stats['mean']:.2f}")

            return {
                "success": True,
                "accuracy": float(accuracy),
                "samples_count": len(samples),
                "spam_count": sum(y),
                "ham_count": len(y) - sum(y),
                "weight_stats": weight_stats
            }

        except Exception as e:
            self.logger.error(f"Training error: {e}")
            return {"success": False, "error": str(e)}

    def create_default_training_data(self) -> List[Dict[str, Any]]:
        """Create default training samples for initial model training"""
        samples = []

        # Spam samples
        spam_samples = [
            {
                'email_data': {
                    'sender_email': 'winner@lottery-scam.tk',
                    'sender_domain': 'lottery-scam.tk',
                    'subject': 'CONGRATULATIONS!!! You won $1,000,000 !!!',
                    'text_content': 'Urgent! You have won the lottery! Click here now to claim your prize of $1,000,000. Act immediately before this offer expires!'
                },
                'is_spam': True
            },
            {
                'email_data': {
                    'sender_email': 'noreply@suspicious.click',
                    'sender_domain': 'suspicious.click',
                    'subject': 'Your account will be suspended - Verify NOW!',
                    'text_content': 'Your account has been compromised. Click this link to verify your password and prevent suspension. Act now!'
                },
                'is_spam': True
            },
            {
                'email_data': {
                    'sender_email': 'prince@nigeria.com',
                    'sender_domain': 'nigeria.com',
                    'subject': 'Urgent Business Proposal - Millions Available',
                    'text_content': 'Dear beneficiary, I am a prince with millions of dollars to transfer. I need your help to transfer funds. You will receive 30% of $10 million.'
                },
                'is_spam': True
            },
            {
                'email_data': {
                    'sender_email': 'pharmacy123@cheap-meds.tk',
                    'sender_domain': 'cheap-meds.tk',
                    'subject': 'Cheap Viagra! 80% OFF!! Limited Time!!!',
                    'text_content': 'Get cheap prescription drugs with no prescription needed! Viagra, Cialis, and more at 80% discount. Order now while supplies last!'
                },
                'is_spam': True
            },
            {
                'email_data': {
                    'sender_email': 'marketing@get-rich-quick.ml',
                    'sender_domain': 'get-rich-quick.ml',
                    'subject': 'Make $5000/month working from home!',
                    'text_content': 'Amazing opportunity to make money from home! No experience required. Make $5000 per month guaranteed! Click here to start earning now!'
                },
                'is_spam': True
            }
        ]

        # Ham (legitimate) samples
        ham_samples = [
            {
                'email_data': {
                    'sender_email': 'support@github.com',
                    'sender_domain': 'github.com',
                    'subject': 'Your pull request has been merged',
                    'text_content': 'Hello, your pull request #123 has been successfully merged into the main branch. Thank you for your contribution!'
                },
                'is_spam': False
            },
            {
                'email_data': {
                    'sender_email': 'notifications@linkedin.com',
                    'sender_domain': 'linkedin.com',
                    'subject': 'You have 3 new connections',
                    'text_content': 'Hi there, you have 3 new connection requests on LinkedIn. View your pending invitations to connect with your network.'
                },
                'is_spam': False
            },
            {
                'email_data': {
                    'sender_email': 'receipts@amazon.com',
                    'sender_domain': 'amazon.com',
                    'subject': 'Your order has shipped',
                    'text_content': 'Your order #123456789 has been shipped and is on its way. You can track your package using the tracking number provided.'
                },
                'is_spam': False
            },
            {
                'email_data': {
                    'sender_email': 'newsletter@company.com',
                    'sender_domain': 'company.com',
                    'subject': 'Monthly newsletter - Product updates',
                    'text_content': 'Here are the latest updates from our team. We have released new features and improvements to our product. Read more about them here.'
                },
                'is_spam': False
            },
            {
                'email_data': {
                    'sender_email': 'team@calendar-app.com',
                    'sender_domain': 'calendar-app.com',
                    'subject': 'Reminder: Meeting tomorrow at 2 PM',
                    'text_content': 'This is a reminder about your scheduled meeting tomorrow at 2:00 PM. Please let us know if you need to reschedule.'
                },
                'is_spam': False
            }
        ]

        samples.extend(spam_samples)
        samples.extend(ham_samples)

        return samples

    def initialize_default_model(self) -> Dict[str, Any]:
        """Initialize model with default training data"""
        if not sklearn_available:
            return {"success": False, "error": "scikit-learn not available"}

        self.logger.info("Initializing ML model with default training data...")
        samples = self.create_default_training_data()
        return self.train_with_samples(samples)

    def _calculate_marketing_score(self, features: Dict[str, float]) -> float:
        """Calculate marketing probability based on specific features"""
        # Weight different marketing indicators
        marketing_score = 0.0

        # Marketing keywords (high weight)
        marketing_keywords = features.get('content_marketing_keywords', 0) + features.get('subject_marketing_keywords', 0)
        marketing_score += min(marketing_keywords * 0.15, 0.5)  # Cap at 0.5

        # Newsletter-specific features
        newsletter_phrases = features.get('content_newsletter_phrases', 0)
        marketing_score += min(newsletter_phrases * 0.1, 0.3)  # Cap at 0.3

        # Tracking URLs (strong indicator)
        tracking_urls = features.get('content_tracking_urls', 0)
        marketing_score += min(tracking_urls * 0.2, 0.4)  # Cap at 0.4

        # Call-to-action phrases
        cta_count = features.get('content_cta_count', 0)
        marketing_score += min(cta_count * 0.08, 0.3)  # Cap at 0.3

        # Price indicators
        price_indicators = features.get('content_price_indicators', 0)
        marketing_score += min(price_indicators * 0.1, 0.2)  # Cap at 0.2

        # Social links
        social_links = features.get('content_social_links', 0)
        marketing_score += min(social_links * 0.05, 0.15)  # Cap at 0.15

        # HTML content (newsletters are often HTML-heavy)
        html_tags = features.get('content_html_tag_count', 0)
        if html_tags > 10:  # Many HTML tags suggest newsletter
            marketing_score += 0.1

        # List-Unsubscribe header (legitimate newsletters have this)
        if features.get('has_list_unsubscribe', 0) > 0:
            marketing_score += 0.15

        return min(marketing_score, 1.0)  # Cap at 1.0

    def _save_model(self):
        """Save trained model and scaler"""
        if self.model and self.scaler:
            try:
                with open(self.model_file, 'wb') as f:
                    pickle.dump(self.model, f)
                with open(self.scaler_file, 'wb') as f:
                    pickle.dump(self.scaler, f)
                # Persist the feature names used to train the scaler/model for alignment
                try:
                    with open(self.feature_names_file, 'w') as fnf:
                        json.dump(self.feature_names, fnf)
                except Exception as e2:
                    self.logger.warning(f"Could not save feature names: {e2}")
                self.logger.debug("Model, scaler, and feature names saved successfully")
            except Exception as e:
                self.logger.error(f"Error saving model: {e}")

    def _load_model(self):
        """Load trained model and scaler"""
        try:
            if self.model_file.exists() and self.scaler_file.exists():
                with open(self.model_file, 'rb') as f:
                    self.model = pickle.load(f)
                with open(self.scaler_file, 'rb') as f:
                    self.scaler = pickle.load(f)
                # Try to load persisted feature names (backward compatible)
                saved_feature_names: Optional[List[str]] = None
                if self.feature_names_file.exists():
                    try:
                        with open(self.feature_names_file, 'r') as fnf:
                            saved_feature_names = json.load(fnf)
                    except Exception as e2:
                        self.logger.debug(f"Could not read saved feature names: {e2}")
                # If mismatch between saved names (or scaler shape) and current extractor names, reinit
                current_len = len(self.feature_names)
                scaler_len = getattr(self.scaler, 'n_features_in_', None)
                saved_len = len(saved_feature_names) if isinstance(saved_feature_names, list) else None
                if (scaler_len is not None and scaler_len != current_len) or (saved_len is not None and saved_len != current_len):
                    self.logger.warning(
                        f"Feature mismatch detected (scaler:{scaler_len}, saved:{saved_len}, current:{current_len}). Reinitializing model with default data.")
                    self.initialize_default_model()
                else:
                    self.model_trained = True
                    self.logger.info("ML model loaded successfully")
            else:
                self.logger.info("No saved model found. Initialize with default data.")
                # Auto-initialize with default data
                self.initialize_default_model()
        except Exception as e:
            self.logger.warning(f"Error loading model: {e}")

    def _save_training_data(self, samples: List[Dict[str, Any]]):
        """Save training data for future reference"""
        try:
            with open(self.training_data_file, 'w') as f:
                json.dump(samples, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving training data: {e}")

    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from trained model"""
        if not self.is_available():
            return {}

        try:
            importances = self.model.feature_importances_
            feature_importance = {}
            for i, feature_name in enumerate(self.feature_names):
                feature_importance[feature_name] = float(importances[i])

            # Sort by importance
            return dict(sorted(feature_importance.items(), key=lambda x: x[1], reverse=True))
        except Exception as e:
            self.logger.error(f"Error getting feature importance: {e}")
            return {}