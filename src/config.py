"""
Secure Configuration Management for ASPM Red Team Engine
Handles API keys, rate limits, and provider configurations
"""
import os
from typing import Dict, Optional
from pydantic import BaseModel, Field
import json
from pathlib import Path


class ProviderConfig(BaseModel):
    """Configuration for a single LLM provider"""
    api_key: str = Field(..., description="API key for the provider")
    base_url: Optional[str] = Field(None, description="Custom base URL if needed")
    max_tokens: int = Field(400, description="Maximum tokens per request")
    rate_limit_rpm: int = Field(60, description="Rate limit requests per minute")
    cost_per_1k_tokens: float = Field(0.002, description="Cost per 1K tokens")


class LLMConfig(BaseModel):
    """Main LLM configuration container"""
    providers: Dict[str, ProviderConfig] = Field(default_factory=dict)
    default_provider: str = Field("gemini/gemini-1.5-flash", description="Default model to use")
    
    @classmethod
    def load_from_env(cls) -> "LLMConfig":
        """Load configuration from environment variables"""
        providers = {}
        
        # OpenAI/GPT Configuration
        if openai_key := os.getenv("OPENAI_API_KEY"):
            providers["gpt-4o"] = ProviderConfig(
                api_key=openai_key,
                cost_per_1k_tokens=0.015
            )
            providers["gpt-4o-mini"] = ProviderConfig(
                api_key=openai_key,
                cost_per_1k_tokens=0.00015
            )
        
        # Anthropic/Claude Configuration
        if anthropic_key := os.getenv("ANTHROPIC_API_KEY"):
            providers["claude-3-sonnet"] = ProviderConfig(
                api_key=anthropic_key,
                base_url="https://api.anthropic.com",
                cost_per_1k_tokens=0.015
            )
            providers["claude-3-haiku"] = ProviderConfig(
                api_key=anthropic_key,
                base_url="https://api.anthropic.com",
                cost_per_1k_tokens=0.00025
            )
        
        # Google/Gemini Configuration
        if gemini_key := os.getenv("GEMINI_API_KEY"):
            providers["gemini/gemini-1.5-pro"] = ProviderConfig(
                api_key=gemini_key,
                cost_per_1k_tokens=0.0035
            )
            providers["gemini/gemini-1.5-flash"] = ProviderConfig(
                api_key=gemini_key,
                cost_per_1k_tokens=0.00015
            )
            providers["gemini/gemini-2.0-flash"] = ProviderConfig(
                api_key=gemini_key,
                cost_per_1k_tokens=0.0
            )
        
        return cls(
            providers=providers,
            default_provider=os.getenv("DEFAULT_LLM_MODEL", "gemini/gemini-1.5-flash")
        )
    
    @classmethod
    def load_from_file(cls, config_path: Path) -> "LLMConfig":
        """Load configuration from JSON file"""
        if not config_path.exists():
            return cls()
        
        with open(config_path) as f:
            data = json.load(f)
        
        providers = {}
        for model, config in data.get("providers", {}).items():
            providers[model] = ProviderConfig(**config)
        
        return cls(
            providers=providers,
            default_provider=data.get("default_provider", "gemini/gemini-1.5-flash")
        )
    
    def save_to_file(self, config_path: Path) -> None:
        """Save configuration to JSON file"""
        data = {
            "providers": {
                model: config.model_dump() for model, config in self.providers.items()
            },
            "default_provider": self.default_provider
        }
        
        with open(config_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_provider_config(self, model: str) -> Optional[ProviderConfig]:
        """Get configuration for a specific model"""
        return self.providers.get(model)
    
    def is_model_available(self, model: str) -> bool:
        """Check if a model is configured"""
        return model in self.providers
    
    def get_available_models(self) -> list:
        """Get list of available models"""
        return list(self.providers.keys())


# Global configuration instance
llm_config = LLMConfig.load_from_env()

# Configuration file path (in project root)
CONFIG_FILE_PATH = Path(__file__).parent.parent / "llm_config.json"
