import re
import logging
from typing import Tuple, List, Optional
from app.config import AppConfig

logger = logging.getLogger("guardrail.inbound")

class InboundInterceptor:
    def __init__(self, config: AppConfig):
        self.config = config.inbound_inspection
        self.enabled = self.config.enabled
        
        # Pre-compile heuristic regexes for low latency
        self.rules = []
        if self.enabled:
            for rule in self.config.heuristic_rules.rules:
                try:
                    compiled = re.compile(rule.pattern, re.IGNORECASE)
                    self.rules.append({
                        "name": rule.name,
                        "pattern": compiled,
                        "weight": rule.weight
                    })
                except Exception as e:
                    logger.error(f"Failed to compile regex rule '{rule.name}' with pattern '{rule.pattern}': {e}")
        
        # Initialize semantic layer
        self.model = None
        self.jailbreak_embeddings = None
        self.fallback_mode = False
        
        if self.enabled and self.config.semantic_inspection.enabled:
            model_name = self.config.semantic_inspection.model_name
            signatures = self.config.semantic_inspection.jailbreak_signatures
            
            logger.info(f"Initializing semantic inspection layer using model '{model_name}'...")
            try:
                # We attempt to import and load sentence-transformers dynamically
                from sentence_transformers import SentenceTransformer
                import torch
                
                # Load the model
                # Note: This might download the model if not cached. We handle errors gracefully.
                self.model = SentenceTransformer(model_name)
                if signatures:
                    # Pre-calculate embeddings for known jailbreak vectors to minimize request latency
                    self.jailbreak_embeddings = self.model.encode(signatures, convert_to_tensor=True)
                    logger.info(f"Pre-computed embeddings for {len(signatures)} jailbreak signatures.")
                else:
                    logger.warning("No semantic jailbreak signatures defined in configuration.")
            except Exception as e:
                logger.warning(
                    f"Could not load local sentence-transformer '{model_name}' due to: {e}. "
                    "Falling back to high-performance heuristic word-similarity."
                )
                self.fallback_mode = True

    def _fallback_similarity(self, prompt: str) -> float:
        """A performant Jaccard token-similarity fallback when torch/transformers isn't loaded."""
        if not self.config.semantic_inspection.jailbreak_signatures:
            return 0.0
            
        def get_tokens(text: str) -> set:
            return set(re.findall(r"\w+", text.lower()))
            
        prompt_tokens = get_tokens(prompt)
        if not prompt_tokens:
            return 0.0
            
        max_sim = 0.0
        for sig in self.config.semantic_inspection.jailbreak_signatures:
            sig_tokens = get_tokens(sig)
            if not sig_tokens:
                continue
            intersection = prompt_tokens.intersection(sig_tokens)
            union = prompt_tokens.union(sig_tokens)
            sim = len(intersection) / len(union) if union else 0.0
            if sim > max_sim:
                max_sim = sim
                
        # Scale Jaccard similarity up to match standard cosine thresholds roughly (e.g. a Jaccard of 0.4 indicates high token overlap)
        return min(max_sim * 1.5, 1.0)

    def inspect(self, prompt: str) -> Tuple[bool, float, List[str]]:
        """
        Inspect an inbound prompt using heuristic regexes and semantic similarity.
        Returns:
            is_blocked (bool)
            max_score (float)
            triggered_rules (list of str)
        """
        if not self.enabled or not prompt:
            return False, 0.0, []
            
        triggered_rules = []
        heuristic_score = 0.0
        
        # 1. Fast heuristic regex layer
        for rule in self.rules:
            if rule["pattern"].search(prompt):
                heuristic_score += rule["weight"]
                triggered_rules.append(f"regex:{rule['name']}")
                
        # 2. Vector semantic similarity layer
        semantic_score = 0.0
        if self.config.semantic_inspection.enabled and self.config.semantic_inspection.jailbreak_signatures:
            if not self.fallback_mode and self.model is not None and self.jailbreak_embeddings is not None:
                try:
                    import torch.nn.functional as F
                    # Calculate vector on-the-fly (low latency since signature embeddings are cached)
                    prompt_emb = self.model.encode(prompt, convert_to_tensor=True)
                    similarities = F.cosine_similarity(prompt_emb.unsqueeze(0), self.jailbreak_embeddings)
                    semantic_score = float(similarities.max().item())
                    
                    if semantic_score >= self.config.semantic_inspection.threshold_similarity:
                        triggered_rules.append(f"semantic_similarity:score={semantic_score:.3f}")
                except Exception as e:
                    logger.error(f"Semantic similarity calculation error: {e}")
                    # Try fallback
                    fallback_sim = self._fallback_similarity(prompt)
                    semantic_score = fallback_sim
                    if fallback_sim >= self.config.semantic_inspection.threshold_similarity:
                        triggered_rules.append(f"semantic_fallback:score={fallback_sim:.3f}")
            else:
                # Fallback path if model not loaded
                fallback_sim = self._fallback_similarity(prompt)
                semantic_score = fallback_sim
                if fallback_sim >= self.config.semantic_inspection.threshold_similarity:
                    triggered_rules.append(f"semantic_fallback:score={fallback_sim:.3f}")
                    
        # Check verdict
        threshold = self.config.heuristic_rules.threshold_score
        is_blocked_heuristic = heuristic_score >= threshold
        is_blocked_semantic = (
            self.config.semantic_inspection.enabled and 
            semantic_score >= self.config.semantic_inspection.threshold_similarity
        )
        
        is_blocked = is_blocked_heuristic or is_blocked_semantic
        max_score = max(heuristic_score, semantic_score)
        
        return is_blocked, max_score, triggered_rules
