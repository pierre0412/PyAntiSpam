"""Feature extraction for spam detection ML models"""

import re
import logging
import time
import math
from typing import Dict, Any, List, Optional
from collections import Counter
from pathlib import Path
import json
import string
from datetime import datetime


class FeatureExtractor:
    """Extracts features from emails for ML spam classification"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.sender_history_file = Path("data/sender_feedback_history.json")
        self.sender_history_cache = None
        self.sender_history_cache_time = 0

        # Common spam keywords
        self.spam_keywords = {
            'urgency': ['urgent', 'immediate', 'act now', 'limited time', 'expires', 'deadline'],
            'money': ['free', 'money', 'cash', 'prize', 'winner', 'lottery', 'million', 'reward'],
            'suspicious': ['click here', 'verify', 'confirm', 'suspended', 'locked', 'update'],
            'phishing': ['login', 'password', 'account', 'security', 'verify', 'suspended'],
            'marketing': ['offer', 'deal', 'discount', 'sale', 'promotion', 'limited', 'subscribe',
                         'newsletter', 'unsubscribe', 'campaign', 'advertising', 'special offer',
                         'best price', 'save money', 'exclusive', 'voucher', 'coupon', 'clearance',
                         'black friday', 'cyber monday', 'flash sale', 'promotional', 'marketing',
                         'commercial', 'advertisement', 'sponsor', 'affiliate', 'bulk', 'blast'],
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
        content_text = email_data.get('body') if email_data.get('body') is not None else email_data.get('text_content', '')
        features.update(self._extract_content_features(content_text))

        # Sender features
        features.update(self._extract_sender_features(email_data))

        # Header-based features (if headers available)
        features.update(self._extract_header_features(email_data))

        # NEW: Sender history features (critical for recurring patterns)
        features.update(self._extract_sender_history_features(email_data))

        # NEW: Temporal features
        features.update(self._extract_temporal_features(email_data))

        # NEW: Advanced text features
        subject = email_data.get('subject', '')
        features.update(self._extract_advanced_text_features(subject, content_text))

        # NEW: Rich content features
        features.update(self._extract_rich_content_features(content_text))

        # NEW: Interaction features (combinations)
        features.update(self._extract_interaction_features(features))

        return features

    def _extract_metadata_features(self, email_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from email metadata"""
        features = {}

        # Subject length
        subject = email_data.get('subject', '')
        features['subject_length'] = len(subject)
        features['subject_word_count'] = len(subject.split())

        # Content length
        content = email_data.get('body') if email_data.get('body') is not None else email_data.get('text_content', '')
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

        # Newsletter/marketing specific features
        features.update(self._extract_newsletter_features(content))

        return features

    def _extract_header_features(self, email_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from raw email headers when available"""
        features: Dict[str, float] = {}
        headers = email_data.get('raw_headers') or {}
        if not isinstance(headers, dict):
            # Ensure headers are a dict-like object
            return {
                'auth_spf_pass': 0.0,
                'auth_dkim_pass': 0.0,
                'auth_dmarc_pass': 0.0,
                'from_dkim_domain_match': 0.0,
                'has_list_unsubscribe': 0.0,
                'replyto_from_mismatch': 0.0,
                'message_id_domain_match': 0.0,
                'received_hops': 0.0,
            }

        # Normalize helper
        def hget(name: str) -> str:
            v = headers.get(name)
            if isinstance(v, list):
                v = "; ".join([str(x) for x in v])
            return str(v or '')

        ar = hget('Authentication-Results').lower()
        features['auth_spf_pass'] = 1.0 if 'spf=pass' in ar else 0.0
        features['auth_dkim_pass'] = 1.0 if 'dkim=pass' in ar else 0.0
        features['auth_dmarc_pass'] = 1.0 if 'dmarc=pass' in ar else 0.0

        # DKIM domain alignment
        import re
        m = re.search(r'd=([^;\s]+)', ar)
        dkim_domain = (m.group(1).lower() if m else '')
        from_domain = (email_data.get('sender_domain') or '').lower()
        features['from_dkim_domain_match'] = 1.0 if dkim_domain and (dkim_domain == from_domain or dkim_domain.endswith('.' + from_domain) or from_domain.endswith('.' + dkim_domain)) else 0.0

        # List-Unsubscribe
        features['has_list_unsubscribe'] = 1.0 if hget('List-Unsubscribe') else 0.0

        # Reply-To mismatch
        reply_to = hget('Reply-To').lower()
        from_addr = (email_data.get('sender_email') or '').lower()
        features['replyto_from_mismatch'] = 1.0 if reply_to and (reply_to not in from_addr) else 0.0

        # Message-ID domain match
        msg_id = hget('Message-ID')
        msg_dom = msg_id.split('@')[-1].strip('>') if '@' in msg_id else ''
        features['message_id_domain_match'] = 1.0 if msg_dom and (msg_dom.lower().endswith(from_domain)) else 0.0

        # Received hops (approximate)
        received = headers.get('Received')
        if isinstance(received, list):
            hops = len(received)
        elif isinstance(received, str):
            # crude heuristic: number of semicolons often equals hops
            hops = received.count(';') if received else 1
        else:
            hops = 0
        features['received_hops'] = float(hops)

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

    def _extract_newsletter_features(self, content: str) -> Dict[str, float]:
        """Extract features specific to newsletters and marketing emails"""
        features = {}
        content_lower = content.lower()

        # Tracking URL patterns (utm parameters, tracking domains)
        tracking_patterns = [
            r'utm_source=', r'utm_medium=', r'utm_campaign=', r'utm_content=',
            r'tracking=', r'track=', r'source=', r'campaign='
        ]
        features['content_tracking_urls'] = sum(
            len(re.findall(pattern, content_lower)) for pattern in tracking_patterns
        )

        # Newsletter-specific phrases
        newsletter_phrases = [
            'unsubscribe', 'opt out', 'manage preferences', 'email preferences',
            'view in browser', 'web version', 'forward to friend', 'share this',
            'newsletter', 'mailing list', 'subscription', 'opt-in'
        ]
        features['content_newsletter_phrases'] = sum(
            content_lower.count(phrase) for phrase in newsletter_phrases
        )

        # Image placeholder patterns (common in HTML newsletters)
        image_patterns = [
            r'<img[^>]*>', r'src=[\'"][^>]*[\'"]', r'alt=[\'"][^>]*[\'"]',
            r'\[image\]', r'\[logo\]', r'\[banner\]'
        ]
        features['content_image_count'] = sum(
            len(re.findall(pattern, content_lower)) for pattern in image_patterns
        )

        # Social media links
        social_patterns = [
            r'facebook\.com', r'twitter\.com', r'linkedin\.com', r'instagram\.com',
            r'youtube\.com', r'social', r'follow us'
        ]
        features['content_social_links'] = sum(
            len(re.findall(pattern, content_lower)) for pattern in social_patterns
        )

        # Marketing call-to-action phrases
        cta_phrases = [
            'buy now', 'shop now', 'order now', 'download now', 'get started',
            'sign up', 'register', 'learn more', 'read more', 'click here'
        ]
        features['content_cta_count'] = sum(
            content_lower.count(phrase) for phrase in cta_phrases
        )

        # Percentage/price indicators
        price_patterns = [
            r'\d+%\s*off', r'\$\d+', r'€\d+', r'£\d+', r'price', r'cost',
            r'save \$', r'discount', r'% discount'
        ]
        features['content_price_indicators'] = sum(
            len(re.findall(pattern, content_lower)) for pattern in price_patterns
        )

        return features

    def _extract_sender_history_features(self, email_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from sender feedback history"""
        features = {}
        sender_email = email_data.get('sender_email', '').lower()

        # Load sender history with caching
        history = self._load_sender_history_cached()
        sender_stats = history.get(sender_email, {})

        if sender_stats:
            spam_count = sender_stats.get('spam_count', 0)
            ham_count = sender_stats.get('ham_count', 0)
            total_feedbacks = spam_count + ham_count

            # Spam ratio (most critical feature)
            features['sender_spam_ratio'] = spam_count / total_feedbacks if total_feedbacks > 0 else 0.0
            features['sender_total_feedbacks'] = float(total_feedbacks)

            # Time-based features
            first_seen = sender_stats.get('first_seen')
            if first_seen:
                try:
                    first_date = datetime.fromisoformat(first_seen)
                    days_since_first = (datetime.now() - first_date).days
                    features['sender_days_since_first'] = float(days_since_first)
                except:
                    features['sender_days_since_first'] = 0.0
            else:
                features['sender_days_since_first'] = 0.0

            # Recurring spammer indicator
            features['sender_is_recurring_spammer'] = 1.0 if spam_count >= 3 else 0.0
            features['sender_is_recurring_ham'] = 1.0 if ham_count >= 3 else 0.0
        else:
            # Unknown sender
            features['sender_spam_ratio'] = 0.0
            features['sender_total_feedbacks'] = 0.0
            features['sender_days_since_first'] = 0.0
            features['sender_is_recurring_spammer'] = 0.0
            features['sender_is_recurring_ham'] = 0.0

        return features

    def _load_sender_history_cached(self) -> Dict[str, Any]:
        """Load sender history with 60-second cache"""
        now = time.time()
        if self.sender_history_cache is None or (now - self.sender_history_cache_time) > 60:
            if self.sender_history_file.exists():
                try:
                    with open(self.sender_history_file, 'r', encoding='utf-8') as f:
                        self.sender_history_cache = json.load(f)
                except Exception as e:
                    self.logger.warning(f"Failed to load sender history: {e}")
                    self.sender_history_cache = {}
            else:
                self.sender_history_cache = {}
            self.sender_history_cache_time = now
        return self.sender_history_cache

    def _extract_temporal_features(self, email_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract time-based features from email"""
        features = {}

        # Try to get timestamp from email_data
        timestamp = email_data.get('timestamp') or email_data.get('date')

        if timestamp:
            try:
                if isinstance(timestamp, str):
                    # Parse timestamp string
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                elif isinstance(timestamp, (int, float)):
                    dt = datetime.fromtimestamp(timestamp)
                else:
                    dt = datetime.now()
            except:
                dt = datetime.now()
        else:
            dt = datetime.now()

        # Hour of day (0-23)
        features['temporal_hour_of_day'] = float(dt.hour)

        # Day of week (0=Monday, 6=Sunday)
        features['temporal_day_of_week'] = float(dt.weekday())

        # Weekend indicator
        features['temporal_is_weekend'] = 1.0 if dt.weekday() >= 5 else 0.0

        # Night time indicator (10pm - 6am)
        features['temporal_is_night_time'] = 1.0 if dt.hour >= 22 or dt.hour < 6 else 0.0

        # Business hours (9am - 5pm, Mon-Fri)
        features['temporal_is_business_hours'] = 1.0 if (dt.weekday() < 5 and 9 <= dt.hour < 17) else 0.0

        return features

    def _extract_advanced_text_features(self, subject: str, content: str) -> Dict[str, float]:
        """Extract advanced text analysis features"""
        features = {}

        combined_text = f"{subject} {content}".lower()
        words = combined_text.split()

        if not words:
            return {
                'text_entropy': 0.0,
                'text_unique_word_ratio': 0.0,
                'text_avg_word_length': 0.0,
                'text_lexical_diversity': 0.0,
                'text_repeated_words': 0.0
            }

        # Text entropy (information density)
        word_freq = Counter(words)
        total_words = len(words)
        entropy = 0.0
        for count in word_freq.values():
            prob = count / total_words
            entropy -= prob * math.log2(prob) if prob > 0 else 0
        features['text_entropy'] = entropy

        # Unique word ratio (vocabulary richness)
        features['text_unique_word_ratio'] = len(word_freq) / total_words if total_words > 0 else 0.0

        # Average word length
        features['text_avg_word_length'] = sum(len(w) for w in words) / total_words if total_words > 0 else 0.0

        # Lexical diversity (unique words / total words)
        features['text_lexical_diversity'] = len(set(words)) / total_words if total_words > 0 else 0.0

        # Repeated word patterns (spam often repeats words)
        repeated_count = sum(1 for count in word_freq.values() if count > 3)
        features['text_repeated_words'] = float(repeated_count)

        return features

    def _extract_rich_content_features(self, content: str) -> Dict[str, float]:
        """Extract features from rich content (HTML, attachments, etc.)"""
        features = {}

        if not content:
            return {
                'rich_html_to_text_ratio': 0.0,
                'rich_has_images': 0.0,
                'rich_has_forms': 0.0,
                'rich_has_scripts': 0.0,
                'rich_link_density': 0.0
            }

        # HTML to text ratio
        html_pattern = r'<[^>]+>'
        html_tags = re.findall(html_pattern, content)
        html_length = sum(len(tag) for tag in html_tags)
        text_length = len(content) - html_length
        features['rich_html_to_text_ratio'] = html_length / len(content) if len(content) > 0 else 0.0

        # Image tags
        features['rich_has_images'] = 1.0 if re.search(r'<img[^>]*>', content, re.IGNORECASE) else 0.0

        # Form tags (phishing indicator)
        features['rich_has_forms'] = 1.0 if re.search(r'<form[^>]*>', content, re.IGNORECASE) else 0.0

        # Script tags (suspicious)
        features['rich_has_scripts'] = 1.0 if re.search(r'<script[^>]*>', content, re.IGNORECASE) else 0.0

        # Link density (links per 100 characters)
        url_pattern = r'https?://[^\s<>\"{}|\\^`[\]]+'
        url_count = len(re.findall(url_pattern, content))
        features['rich_link_density'] = (url_count * 100) / len(content) if len(content) > 0 else 0.0

        return features

    def _extract_interaction_features(self, features: Dict[str, float]) -> Dict[str, float]:
        """Extract interaction features (combinations of existing features)"""
        interaction_features = {}

        # Marketing newsletter with unsubscribe link (legitimate marketing)
        has_marketing = features.get('content_marketing_keywords', 0) > 0
        has_newsletter = features.get('content_newsletter_phrases', 0) > 0
        interaction_features['interaction_marketing_newsletter'] = 1.0 if (has_marketing and has_newsletter) else 0.0

        # Suspicious content without authentication
        has_suspicious = features.get('content_suspicious_keywords', 0) > 0
        no_auth = (features.get('auth_spf_pass', 0) == 0 and
                   features.get('auth_dkim_pass', 0) == 0 and
                   features.get('auth_dmarc_pass', 0) == 0)
        interaction_features['interaction_suspicious_no_auth'] = 1.0 if (has_suspicious and no_auth) else 0.0

        # Urgency with money keywords (classic spam)
        has_urgency = features.get('content_urgency_keywords', 0) > 0
        has_money = features.get('content_money_keywords', 0) > 0
        interaction_features['interaction_urgency_money'] = 1.0 if (has_urgency and has_money) else 0.0

        # Known spammer with suspicious content
        is_spammer = features.get('sender_is_recurring_spammer', 0) == 1.0
        interaction_features['interaction_spammer_suspicious'] = 1.0 if (is_spammer and has_suspicious) else 0.0

        # High caps ratio with many exclamations (shouting)
        high_caps = features.get('subject_caps_ratio', 0) > 0.5
        many_exclamations = features.get('subject_exclamation_count', 0) > 2
        interaction_features['interaction_shouting'] = 1.0 if (high_caps and many_exclamations) else 0.0

        return interaction_features

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

        # Header-based features
        feature_names.extend([
            'auth_spf_pass', 'auth_dkim_pass', 'auth_dmarc_pass',
            'from_dkim_domain_match', 'has_list_unsubscribe',
            'replyto_from_mismatch', 'message_id_domain_match', 'received_hops'
        ])

        # Newsletter-specific features
        feature_names.extend([
            'content_tracking_urls', 'content_newsletter_phrases', 'content_image_count',
            'content_social_links', 'content_cta_count', 'content_price_indicators'
        ])

        # Sender history features
        feature_names.extend([
            'sender_spam_ratio', 'sender_total_feedbacks', 'sender_days_since_first',
            'sender_is_recurring_spammer', 'sender_is_recurring_ham'
        ])

        # Temporal features
        feature_names.extend([
            'temporal_hour_of_day', 'temporal_day_of_week', 'temporal_is_weekend',
            'temporal_is_night_time', 'temporal_is_business_hours'
        ])

        # Advanced text features
        feature_names.extend([
            'text_entropy', 'text_unique_word_ratio', 'text_avg_word_length',
            'text_lexical_diversity', 'text_repeated_words'
        ])

        # Rich content features
        feature_names.extend([
            'rich_html_to_text_ratio', 'rich_has_images', 'rich_has_forms',
            'rich_has_scripts', 'rich_link_density'
        ])

        # Interaction features
        feature_names.extend([
            'interaction_marketing_newsletter', 'interaction_suspicious_no_auth',
            'interaction_urgency_money', 'interaction_spammer_suspicious',
            'interaction_shouting'
        ])

        return sorted(feature_names)