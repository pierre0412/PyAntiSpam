"""Feature extraction for spam detection ML models"""

import re
import logging
from typing import Dict, Any, List
from collections import Counter
import string


class FeatureExtractor:
    """Extracts features from emails for ML spam classification"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Common spam keywords
        self.spam_keywords = {
            'urgency': ['urgent', 'immediate', 'act now', 'limited time', 'expires', 'deadline'],
            'money': ['free', 'money', 'cash', 'prize', 'winner', 'lottery', 'million', 'reward'],
            'suspicious': ['click here', 'verify', 'confirm', 'suspended', 'locked', 'update'],
            'phishing': ['login', 'password', 'account', 'security', 'verify', 'suspended'],
            'marketing': ['offer', 'deal', 'discount', 'sale', 'promotion', 'limited'],
            'scam': ['nigerian', 'inheritance', 'beneficiary', 'transfer', 'funds']
        }

        # Suspicious TLDs
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download']

    def extract_features(self, email_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from email data"""
        features = {}

        # Email metadata features
        features.update(self._extract_metadata_features(email_data))

        # Subject line features
        features.update(self._extract_subject_features(email_data.get('subject', '')))

        # Content features
        features.update(self._extract_content_features(email_data.get('text_content', '')))

        # Sender features
        features.update(self._extract_sender_features(email_data))

        return features

    def _extract_metadata_features(self, email_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from email metadata"""
        features = {}

        # Subject length
        subject = email_data.get('subject', '')
        features['subject_length'] = len(subject)
        features['subject_word_count'] = len(subject.split())

        # Content length
        content = email_data.get('text_content', '')
        features['content_length'] = len(content)
        features['content_word_count'] = len(content.split())

        # Ratio features
        if features['content_length'] > 0:
            features['subject_to_content_ratio'] = features['subject_length'] / features['content_length']
        else:
            features['subject_to_content_ratio'] = 0

        return features

    def _extract_subject_features(self, subject: str) -> Dict[str, float]:
        """Extract features from subject line"""
        features = {}
        subject_lower = subject.lower()

        # All caps ratio
        if len(subject) > 0:
            features['subject_caps_ratio'] = sum(1 for c in subject if c.isupper()) / len(subject)
        else:
            features['subject_caps_ratio'] = 0

        # Exclamation marks
        features['subject_exclamation_count'] = subject.count('!')
        features['subject_question_count'] = subject.count('?')

        # Spam keyword detection
        for category, keywords in self.spam_keywords.items():
            count = sum(1 for keyword in keywords if keyword in subject_lower)
            features[f'subject_{category}_keywords'] = count

        # Special characters
        features['subject_special_chars'] = sum(1 for c in subject if c in string.punctuation)

        # Suspicious patterns
        features['subject_has_re'] = 1.0 if subject_lower.startswith(('re:', 'fwd:')) else 0.0
        features['subject_has_brackets'] = 1.0 if '[' in subject or ']' in subject else 0.0

        return features

    def _extract_content_features(self, content: str) -> Dict[str, float]:
        """Extract features from email content"""
        features = {}
        content_lower = content.lower()

        if not content:
            return {f'content_{key}': 0.0 for key in [
                'caps_ratio', 'exclamation_count', 'url_count', 'email_count',
                'phone_count', 'number_count', 'line_count', 'avg_line_length'
            ] + [f'{cat}_keywords' for cat in self.spam_keywords.keys()]}

        # Caps ratio
        features['content_caps_ratio'] = sum(1 for c in content if c.isupper()) / len(content)

        # Punctuation
        features['content_exclamation_count'] = content.count('!')
        features['content_question_count'] = content.count('?')

        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`[\]]+|www\.[^\s<>"{}|\\^`[\]]+'
        urls = re.findall(url_pattern, content_lower)
        features['content_url_count'] = len(urls)

        # Check for suspicious TLDs
        features['content_suspicious_tld_count'] = 0
        for url in urls:
            for tld in self.suspicious_tlds:
                if tld in url:
                    features['content_suspicious_tld_count'] += 1
                    break

        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        features['content_email_count'] = len(re.findall(email_pattern, content))

        # Phone numbers (simple pattern)
        phone_pattern = r'(\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}'
        features['content_phone_count'] = len(re.findall(phone_pattern, content))

        # Numbers (could indicate prices, percentages, etc.)
        number_pattern = r'\b\d+\b'
        features['content_number_count'] = len(re.findall(number_pattern, content))

        # Text structure
        lines = content.split('\n')
        features['content_line_count'] = len(lines)
        if lines:
            features['content_avg_line_length'] = sum(len(line) for line in lines) / len(lines)
        else:
            features['content_avg_line_length'] = 0

        # Spam keywords in content
        for category, keywords in self.spam_keywords.items():
            count = sum(content_lower.count(keyword) for keyword in keywords)
            features[f'content_{category}_keywords'] = count

        # HTML tags (if present)
        html_pattern = r'<[^>]+>'
        features['content_html_tag_count'] = len(re.findall(html_pattern, content))

        return features

    def _extract_sender_features(self, email_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from sender information"""
        features = {}

        sender_email = email_data.get('sender_email', '').lower()
        sender_domain = email_data.get('sender_domain', '').lower()

        # Domain features
        features['sender_suspicious_tld'] = 0.0
        for tld in self.suspicious_tlds:
            if sender_domain.endswith(tld):
                features['sender_suspicious_tld'] = 1.0
                break

        # Email structure
        if '@' in sender_email:
            local_part = sender_email.split('@')[0]
            features['sender_local_length'] = len(local_part)
            features['sender_has_numbers'] = 1.0 if any(c.isdigit() for c in local_part) else 0.0
            features['sender_has_special_chars'] = 1.0 if any(c in '._-+' for c in local_part) else 0.0
        else:
            features['sender_local_length'] = 0
            features['sender_has_numbers'] = 0.0
            features['sender_has_special_chars'] = 0.0

        # Domain length
        features['sender_domain_length'] = len(sender_domain)

        # Common legitimate domains
        legitimate_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com']
        features['sender_legitimate_domain'] = 1.0 if sender_domain in legitimate_domains else 0.0

        return features

    def get_feature_names(self) -> List[str]:
        """Get list of all possible feature names"""
        # This should match the features extracted above
        feature_names = [
            # Metadata
            'subject_length', 'subject_word_count', 'content_length',
            'content_word_count', 'subject_to_content_ratio',

            # Subject features
            'subject_caps_ratio', 'subject_exclamation_count', 'subject_question_count',
            'subject_special_chars', 'subject_has_re', 'subject_has_brackets',

            # Content features
            'content_caps_ratio', 'content_exclamation_count', 'content_question_count',
            'content_url_count', 'content_suspicious_tld_count', 'content_email_count',
            'content_phone_count', 'content_number_count', 'content_line_count',
            'content_avg_line_length', 'content_html_tag_count',

            # Sender features
            'sender_suspicious_tld', 'sender_local_length', 'sender_has_numbers',
            'sender_has_special_chars', 'sender_domain_length', 'sender_legitimate_domain'
        ]

        # Add keyword features
        for category in self.spam_keywords.keys():
            feature_names.extend([f'subject_{category}_keywords', f'content_{category}_keywords'])

        return sorted(feature_names)