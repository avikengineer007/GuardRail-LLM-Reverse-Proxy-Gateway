import os
import yaml
from typing import List, Optional
from pydantic import BaseModel, Field

class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    upstream_url: str = "https://api.openai.com"

class HeuristicRule(BaseModel):
    name: str
    pattern: str
    weight: float

class HeuristicRulesConfig(BaseModel):
    threshold_score: float = 1.0
    rules: List[HeuristicRule] = []

class SemanticInspectionConfig(BaseModel):
    enabled: bool = True
    threshold_similarity: float = 0.78
    model_name: str = "all-MiniLM-L6-v2"
    jailbreak_signatures: List[str] = []

class InboundInspectionConfig(BaseModel):
    enabled: bool = True
    heuristic_rules: HeuristicRulesConfig = Field(default_factory=HeuristicRulesConfig)
    semantic_inspection: SemanticInspectionConfig = Field(default_factory=SemanticInspectionConfig)

class EntropyScannerConfig(BaseModel):
    enabled: bool = True
    min_length: int = 20
    entropy_threshold: float = 4.5

class RegexRule(BaseModel):
    name: str
    pattern: str
    placeholder: str

class OutboundInspectionConfig(BaseModel):
    enabled: bool = True
    action: str = "redact"  # "redact" or "block"
    entropy_scanner: EntropyScannerConfig = Field(default_factory=EntropyScannerConfig)
    regex_rules: List[RegexRule] = []

class AppConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    inbound_inspection: InboundInspectionConfig = Field(default_factory=InboundInspectionConfig)
    outbound_inspection: OutboundInspectionConfig = Field(default_factory=OutboundInspectionConfig)

def load_config(config_path: str = "config.yaml") -> AppConfig:
    """Load and parse YAML configuration into a validated Pydantic model."""
    config_path = os.getenv("GUARDRAIL_CONFIG_PATH", config_path)
    if not os.path.exists(config_path):
        # Fallback to look up in parent directories if run from subdirectories
        search_paths = [config_path, "../config.yaml", "config.yaml"]
        for sp in search_paths:
            if os.path.exists(sp):
                config_path = sp
                break
    
    if not os.path.exists(config_path):
        print(f"Warning: Configuration file '{config_path}' not found. Loading defaults.")
        return AppConfig()
        
    with open(config_path, "r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f)
            return AppConfig(**data)
        except Exception as e:
            print(f"Error parsing '{config_path}': {e}. Using defaults.")
            return AppConfig()
