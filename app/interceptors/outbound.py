import re
import math
import logging
from collections import Counter
from typing import Tuple, List, Optional
from app.config import AppConfig

logger = logging.getLogger("guardrail.outbound")

class OutboundInterceptor:
    def __init__(self, config: AppConfig):
        self.config = config.outbound_inspection
        self.enabled = self.config.enabled
        self.action = self.config.action.lower()  # "redact" or "block"
        
        # Compile PII and API key regex rules
        self.rules = []
        if self.enabled:
            for rule in self.config.regex_rules:
                try:
                    compiled = re.compile(rule.pattern)
                    self.rules.append({
                        "name": rule.name,
                        "pattern": compiled,
                        "placeholder": rule.placeholder
                    })
                except Exception as e:
                    logger.error(f"Failed to compile outbound regex '{rule.name}': {e}")
                    
        # Setup entropy scanner
        self.entropy_enabled = self.config.entropy_scanner.enabled
        self.min_length = self.config.entropy_scanner.min_length
        self.entropy_threshold = self.config.entropy_scanner.entropy_threshold
        
        # Token extraction pattern for high entropy search (find long contiguous blocks of base64/hex/alphanumeric characters)
        self.token_extractor = re.compile(r"[A-Za-z0-9+/=_-]{16,128}")

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        counts = Counter(text)
        total = len(text)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    def inspect_and_process(self, text: str) -> Tuple[str, bool, List[str]]:
        """
        Inspect outgoing LLM response text for PII and high-entropy secrets.
        Returns:
            processed_text (str): Redacted text (or same text if not redacting)
            is_blocked (bool): True if the action is block and an issue was found
            triggered_rules (list of str): List of triggered rule descriptions
        """
        if not self.enabled or not text:
            return text, False, []
            
        triggered_rules = []
        should_mitigate = False
        redacted_text = text

        # 1. Check Regex Rules (PII and API keys)
        for rule in self.rules:
            matches = rule["pattern"].findall(redacted_text)
            if matches:
                should_mitigate = True
                triggered_rules.append(f"regex:{rule['name']}")
                # If we redact, substitute all occurrences
                if self.action == "redact":
                    # If match is a tuple (e.g. group match), handle replacing correctly
                    # For simple replacement, sub works perfectly
                    redacted_text = rule["pattern"].sub(rule["placeholder"], redacted_text)

        # 2. Check Entropy Scanner (Secrets and Keys)
        if self.entropy_enabled:
            # Find candidate tokens
            candidates = self.token_extractor.findall(text)
            for candidate in candidates:
                # Exclude strings that look like standard words or placeholders
                if len(candidate) >= self.min_length:
                    # Exclude the placeholders we just inserted to avoid double redaction
                    is_placeholder = False
                    for rule in self.rules:
                        if rule["placeholder"] in candidate or candidate in rule["placeholder"]:
                            is_placeholder = True
                            break
                    if is_placeholder:
                        continue
                        
                    entropy = self.calculate_entropy(candidate)
                    if entropy >= self.entropy_threshold:
                        # Double check we don't flag normal English text
                        # Standard English text of length >= 20 has low entropy because letters are not evenly distributed.
                        # Random base64/hex keys have high entropy.
                        should_mitigate = True
                        triggered_rules.append(f"entropy:token={candidate[:8]}...[len={len(candidate)},entropy={entropy:.2f}]")
                        
                        if self.action == "redact":
                            placeholder = "[REDACTED_HIGH_ENTROPY_KEY]"
                            redacted_text = redacted_text.replace(candidate, placeholder)

        # Final verdict application
        if should_mitigate:
            if self.action == "block":
                return text, True, triggered_rules
            else:
                return redacted_text, False, triggered_rules
                
        return text, False, []
