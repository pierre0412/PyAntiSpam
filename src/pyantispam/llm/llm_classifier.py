"""LLM-based spam classification using OpenAI and Anthropic APIs"""

import logging
import os
from typing import Dict, Any, Optional
import json

try:
    import openai
except ImportError:
    openai = None

try:
    import anthropic
except ImportError:
    anthropic = None


class LLMClassifier:
    """LLM-based spam classifier supporting OpenAI and Anthropic models"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Initialize clients
        self.openai_client = None
        self.anthropic_client = None

        self._initialize_clients()

    def _initialize_clients(self):
        """Initialize LLM API clients based on configuration"""

        # OpenAI client
        openai_api_key = os.getenv('OPENAI_API_KEY')
        if openai_api_key and openai:
            try:
                self.openai_client = openai.OpenAI(api_key=openai_api_key)
                self.logger.info("OpenAI client initialized successfully")
            except Exception as e:
                self.logger.warning(f"Failed to initialize OpenAI client: {e}")

        # Anthropic client
        anthropic_api_key = os.getenv('ANTHROPIC_API_KEY')
        if anthropic_api_key and anthropic:
            try:
                self.anthropic_client = anthropic.Anthropic(api_key=anthropic_api_key)
                self.logger.info("Anthropic client initialized successfully")
            except Exception as e:
                self.logger.warning(f"Failed to initialize Anthropic client: {e}")

        if not self.openai_client and not self.anthropic_client:
            self.logger.warning("No LLM clients initialized. Please set API keys in environment variables.")

    def classify(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Classify email as spam or not using LLM"""

        # Check if any client is available
        if not self.openai_client and not self.anthropic_client:
            return {
                "action": "KEEP",
                "reason": "No LLM API keys configured",
                "confidence": 0.5,
                "method": "llm_unavailable"
            }

        # Prepare email content for analysis
        email_text = self._prepare_email_text(email_data)

        # Try classification with available providers
        provider = self.config.get("llm.provider", "openai").lower()

        if provider == "anthropic" and self.anthropic_client:
            return self._classify_with_anthropic(email_text, email_data)
        elif provider == "openai" and self.openai_client:
            return self._classify_with_openai(email_text, email_data)
        else:
            # Fallback to any available client
            if self.openai_client:
                return self._classify_with_openai(email_text, email_data)
            elif self.anthropic_client:
                return self._classify_with_anthropic(email_text, email_data)

        return {
            "action": "KEEP",
            "reason": "LLM classification failed",
            "confidence": 0.5,
            "method": "llm_error"
        }

    def _prepare_email_text(self, email_data: Dict[str, Any]) -> str:
        """Prepare email text for LLM analysis"""
        parts = []

        sender_email = email_data.get("sender_email", "")
        if sender_email:
            parts.append(f"From: {sender_email}")

            # Extract domain for spoofing analysis
            sender_domain = sender_email.split('@')[-1].lower() if '@' in sender_email else ""
            if sender_domain:
                parts.append(f"Sender Domain: {sender_domain}")

        if email_data.get("subject"):
            subject = email_data['subject']
            parts.append(f"Subject: {subject}")

            # Analyze potential brand impersonation in subject
            self._add_brand_analysis(parts, subject, sender_email)

        # Use body if available; fallback to text_content for backward-compat
        content = email_data.get("body") if email_data.get("body") is not None else email_data.get("text_content")
        if content:
            # Limit content length to avoid token limits
            if len(content) > 2000:
                content = content[:2000] + "... [truncated]"
            parts.append(f"Content: {content}")

        # Concise header summary for key signals (if available)
        headers = email_data.get("raw_headers") or {}
        if isinstance(headers, dict) and headers:
            ar = str(headers.get("Authentication-Results", ""))
            ar_snip = ar[:300]
            lu_present = "present" if headers.get("List-Unsubscribe") else "absent"
            reply_to = str(headers.get("Reply-To", "")).lower()
            from_addr = str(email_data.get("sender_email", "")).lower()
            reply_mismatch = "yes" if (reply_to and reply_to not in from_addr) else "no"

            # Add Return-Path analysis if available
            return_path = str(headers.get("Return-Path", "")).lower()
            return_path_mismatch = "yes" if (return_path and return_path not in from_addr) else "no"

            parts.append(f"Headers: Auth={ar_snip} | List-Unsubscribe={lu_present} | ReplyToMismatch={reply_mismatch} | ReturnPathMismatch={return_path_mismatch}")

        return "\n".join(parts)

    def _add_brand_analysis(self, parts: list, subject: str, sender_email: str) -> None:
        """Add brand impersonation analysis"""
        # Common brand keywords that are often impersonated
        brand_keywords = [
            # Banks
            'credit agricole', 'creditagricole', 'ca-bank', 'cabank',
            'bnp paribas', 'bnpparibas', 'societe generale', 'societegenerale',
            'banque populaire', 'banquepopulaire', 'lcl', 'cic',

            # Services
            'paypal', 'amazon', 'ebay', 'microsoft', 'google', 'apple',
            'facebook', 'instagram', 'linkedin', 'twitter',

            # French services
            'ovh', 'ovhcloud', 'orange', 'sfr', 'bouygues', 'free',
            'edf', 'engie', 'la poste', 'laposte', 'sncf',
            'caf', 'cpam', 'ameli', 'pole emploi', 'impots', 'dgfip'
        ]

        subject_lower = subject.lower()
        sender_lower = sender_email.lower()

        # Check if subject mentions a brand but sender domain doesn't match
        for brand in brand_keywords:
            if brand in subject_lower or brand.replace(' ', '') in subject_lower:
                # Check if sender domain matches the brand
                brand_clean = brand.replace(' ', '').replace('-', '')
                if brand_clean not in sender_lower:
                    parts.append(f"⚠️ BRAND MISMATCH: Subject mentions '{brand}' but sender is {sender_email}")
                    break

    def _classify_with_openai(self, email_text: str, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Classify using OpenAI API"""
        try:
            model = self.config.get("llm.model", "gpt-4.1-nano")

            system_prompt = (
                "You are an expert email security analyst. Output JSON only (minified, one object), no extra text or markdown.\n"
                "Schema: {\"is_spam\": boolean, \"confidence\": number 0..1, \"reason\": string}.\n\n"
                "SPAM INDICATORS (be aggressive on detection):\n"
                "• PHISHING: fake login pages, account suspension threats, urgent security alerts, credential harvesting, "
                "brand impersonation (banks, social media, services), suspicious authentication requests\n"
                "• MALWARE/VIRUS: suspicious attachments (.exe, .zip, .scr), shortened/suspicious URLs, "
                "download prompts, fake software updates, malicious redirects\n"
                "• MARKETING/COMMERCIAL: unsolicited newsletters, promotional blasts, sales pitches, "
                "unsubscribe from unknown lists, bulk commercial content, affiliate marketing\n"
                "• SCAMS: money transfers, crypto schemes, inheritance scams, lottery wins, "
                "investment opportunities, romance scams, fake charities\n"
                "• SOCIAL ENGINEERING: urgent action required, fear tactics, authority impersonation, "
                "personal info requests, pressure to click/download/respond quickly\n"
                "• TECHNICAL: domain spoofing, reply-to mismatches, poor SPF/DKIM, suspicious headers\n"
                "• DOMAIN SPOOFING: brand mentions in subject/content but sender domain doesn't match "
                "(e.g., 'OVH' email from ovhcloud@gmail.com, 'Crédit Agricole' from creditagrlcole.fr)\n\n"
                "LEGITIMATE indicators: transactional emails from known services, expected communications, "
                "proper authentication, recognized brands with matching domains.\n\n"
                "Be STRICT: when in doubt between spam/legitimate, prefer marking as spam for safety.\n"
                "Examples: {\"is_spam\":true,\"confidence\":0.95,\"reason\":\"Phishing: fake bank login with urgent tone\"} "
                "| {\"is_spam\":true,\"confidence\":0.87,\"reason\":\"Marketing: unsolicited promotional blast\"}"
            )
            user_prompt = (
                "Analyse l'email ci-dessous et rends UNIQUEMENT le JSON (un seul objet).\n\n"
                f"{email_text}\n\n"
                "Rappels: **retournes un JSON strict, minifié, champs exacts: is_spam, confidence, reason.**"
            )

            response = self.openai_client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                #max_completion_tokens=200
            )

            result_text = response.choices[0].message.content.strip()

            # Try to parse JSON response
            try:
                result = json.loads(result_text)
                is_spam = result.get("is_spam", False)
                confidence = max(0.0, min(1.0, result.get("confidence", 0.5)))
                reason = result.get("reason", "LLM analysis")

                return {
                    "action": "SPAM" if is_spam else "KEEP",
                    "reason": f"OpenAI: {reason}",
                    "confidence": confidence,
                    "method": "llm_openai"
                }

            except json.JSONDecodeError:
                # Fallback if JSON parsing fails
                is_spam = "spam" in result_text.lower() or "yes" in result_text.lower()
                return {
                    "action": "SPAM" if is_spam else "KEEP",
                    "reason": f"OpenAI: {result_text[:100]}",
                    "confidence": 0.7,
                    "method": "llm_openai"
                }

        except Exception as e:
            self.logger.error(f"OpenAI classification error: {e}")
            return {
                "action": "KEEP",
                "reason": f"OpenAI error: {str(e)[:50]}",
                "confidence": 0.5,
                "method": "llm_openai_error"
            }

    def _classify_with_anthropic(self, email_text: str, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Classify using Anthropic API"""
        try:
            model = self.config.get("llm.model", "claude-3-haiku-20240307")

            prompt = f"""You are an expert email security analyst specializing in threat detection. Analyze this email and determine if it's spam.

Email to analyze:
{email_text}

Respond with JSON in this exact format:
{{
    "is_spam": true/false,
    "confidence": 0.0-1.0,
    "reason": "detailed explanation"
}}

COMPREHENSIVE THREAT ANALYSIS - Be AGGRESSIVE in detection:

🎯 PHISHING & SECURITY THREATS:
- Account suspension/verification scams, fake login pages
- Brand impersonation (banks, PayPal, social media, cloud services)
- Credential harvesting, fake 2FA/OTP requests
- Suspicious authentication alerts, fake security warnings

🦠 MALWARE & MALICIOUS CONTENT:
- Dangerous attachments (.exe, .zip, .scr, .bat, .com)
- Suspicious download links, fake software updates
- URL shorteners, suspicious redirects, typosquatting domains
- Fake document sharing (fake Google Drive, Dropbox links)

📧 MARKETING & COMMERCIAL SPAM:
- Unsolicited newsletters, promotional blasts
- Affiliate marketing, MLM schemes
- Unsubscribe from unknown senders, bulk commercial content
- Cold sales pitches, lead generation emails

💰 SCAMS & FRAUD:
- Money transfer requests, inheritance scams, lottery wins
- Cryptocurrency schemes, investment opportunities
- Romance scams, fake charity requests
- Business email compromise (BEC) attempts

🎭 SOCIAL ENGINEERING:
- Urgent action required, fear-based messaging
- Authority impersonation (CEO, IT support, government)
- Pressure tactics, time-sensitive offers
- Personal information requests, survey scams

🔍 TECHNICAL INDICATORS:
- SPF/DKIM/DMARC failures, domain spoofing
- Reply-to address mismatches, suspicious headers
- Poor grammar/spelling in professional contexts
- Generic greetings from supposed known contacts

🚨 DOMAIN SPOOFING & BRAND IMPERSONATION:
- Brand names in subject but sender domain doesn't match official domain
- Examples: "OVH" email from ovhcloud@gmail.com, "Crédit Agricole" from creditagrlcole.fr
- Typosquatting: creditagricole.com vs creditagrlcole.fr, paypal vs paypaI (with capital i)
- Wrong TLD: paypal.net instead of paypal.com, amazon.co instead of amazon.fr
- Pay attention to ⚠️ BRAND MISMATCH warnings in email data

DECISION RULE: When uncertain, PREFER marking as spam for user safety. Only mark as legitimate if clearly expected/transactional."""

            response = self.anthropic_client.messages.create(
                model=model,
                max_tokens=200,
                temperature=0.1,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            result_text = response.content[0].text.strip()

            # Try to parse JSON response
            try:
                result = json.loads(result_text)
                is_spam = result.get("is_spam", False)
                confidence = max(0.0, min(1.0, result.get("confidence", 0.5)))
                reason = result.get("reason", "LLM analysis")

                return {
                    "action": "SPAM" if is_spam else "KEEP",
                    "reason": f"Claude: {reason}",
                    "confidence": confidence,
                    "method": "llm_anthropic"
                }

            except json.JSONDecodeError:
                # Fallback if JSON parsing fails
                is_spam = "spam" in result_text.lower() or "true" in result_text.lower()
                return {
                    "action": "SPAM" if is_spam else "KEEP",
                    "reason": f"Claude: {result_text[:100]}",
                    "confidence": 0.7,
                    "method": "llm_anthropic"
                }

        except Exception as e:
            self.logger.error(f"Anthropic classification error: {e}")
            return {
                "action": "KEEP",
                "reason": f"Claude error: {str(e)[:50]}",
                "confidence": 0.5,
                "method": "llm_anthropic_error"
            }

    def is_available(self) -> bool:
        """Check if LLM classification is available"""
        return self.openai_client is not None or self.anthropic_client is not None