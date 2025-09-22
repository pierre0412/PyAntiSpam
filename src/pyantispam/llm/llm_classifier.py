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

        if email_data.get("sender_email"):
            parts.append(f"From: {email_data['sender_email']}")

        if email_data.get("subject"):
            parts.append(f"Subject: {email_data['subject']}")

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
            parts.append(f"Headers: Auth={ar_snip} | List-Unsubscribe={lu_present} | ReplyToMismatch={reply_mismatch}")

        return "\n".join(parts)

    def _classify_with_openai(self, email_text: str, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Classify using OpenAI API"""
        try:
            model = self.config.get("llm.openai_model", "gpt-5-nano")

            system_prompt = (
                "You are a concise spam filter for email classification. "
                "Output JSON only (minified, one object), no extra text or markdown.\n"
                "Schema: {\"is_spam\": boolean, \"confidence\": number 0..1, \"reason\": string}.\n"
                "Criteria (non-exhaustive): suspicious sender/domain, phishing, login/OTP/password reset bait, "
                "malicious links/attachments, scam money/crypto, too-good-to-be-true offers, urgency/threats, "
                "requests for personal data, poor grammar, marketing blast patterns.\n"
                "Tie-breaking: if clearly legitimate (known brands, transactional, expected context) -> is_spam=false; "
                "if clearly deceptive/harmful -> is_spam=true; else use best judgment and set confidence around 0.5.\n"
                "Examples of valid outputs: {\"is_spam\":true,\"confidence\":0.92,\"reason\":\"Phishing link, urgent account suspension\"} "
                "| {\"is_spam\":false,\"confidence\":0.81,\"reason\":\"Receipt from trusted domain\"}"
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
            model = self.config.get("llm.anthropic_model", "claude-3-haiku-20240307")

            prompt = f"""You are a spam detection expert. Analyze this email and determine if it's spam.

Email to analyze:
{email_text}

Please respond with JSON in this format:
{{
    "is_spam": true/false,
    "confidence": 0.0-1.0,
    "reason": "explanation"
}}

Consider spam indicators like suspicious senders, phishing attempts, malicious content, poor grammar, urgency tactics, and requests for personal information."""

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