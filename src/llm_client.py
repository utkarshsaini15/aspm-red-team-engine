"""
Enhanced LLM Client with Real API Integration
Handles multiple providers, rate limiting, cost tracking, and error handling
"""
import asyncio
import time
import litellm
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from src.config import llm_config, ProviderConfig


@dataclass
class LLMResponse:
    """Standardized response format from any LLM provider"""
    content: str
    model: str
    tokens_used: int
    latency: float
    cost: float
    provider: str
    error: Optional[str] = None


class RateLimiter:
    """Simple rate limiter for API calls"""
    def __init__(self, requests_per_minute: int):
        self.rpm = requests_per_minute
        self.requests = []
    
    async def acquire(self):
        """Wait if rate limit would be exceeded"""
        now = time.time()
        # Remove requests older than 1 minute
        self.requests = [req_time for req_time in self.requests if now - req_time < 60]
        
        if len(self.requests) >= self.rpm:
            # Calculate wait time
            oldest_request = min(self.requests)
            wait_time = 60 - (now - oldest_request)
            if wait_time > 0:
                await asyncio.sleep(wait_time)
        
        self.requests.append(now)


class LLMClient:
    """Enhanced LLM client with real API integration"""
    
    def __init__(self):
        self.rate_limiters: Dict[str, RateLimiter] = {}
        self.total_cost = 0.0
        self.request_count = 0
        
        # Initialize rate limiters for each provider
        for model, config in llm_config.providers.items():
            self.rate_limiters[model] = RateLimiter(config.rate_limit_rpm)
    
    def _get_provider_from_model(self, model: str) -> str:
        """Extract provider name from model"""
        if model.startswith("gpt-"):
            return "openai"
        elif model.startswith("claude-"):
            return "anthropic"
        elif model.startswith("gemini-"):
            return "google"
        else:
            return "unknown"
    
    def _calculate_cost(self, model: str, tokens: int) -> float:
        """Calculate cost for API call"""
        config = llm_config.get_provider_config(model)
        if not config:
            return 0.0
        
        return (tokens / 1000) * config.cost_per_1k_tokens
    
    async def call_llm(
        self,
        model: str,
        messages: list,
        temperature: float = 0.7,
        max_tokens: int = 400,
        api_key: str = None
    ) -> LLMResponse:
        """
        Make a real API call to the specified LLM model
        """
        # Check if model is configured
        if not llm_config.is_model_available(model):
            return LLMResponse(
                content="",
                model=model,
                tokens_used=0,
                latency=0.0,
                cost=0.0,
                provider="unknown",
                error=f"Model {model} not configured. Please add API key."
            )
        
        # Get provider config
        config = llm_config.get_provider_config(model)
        provider = self._get_provider_from_model(model)
        
        # Rate limiting
        rate_limiter = self.rate_limiters.get(model)
        if rate_limiter:
            await rate_limiter.acquire()
        
        # Prepare API call
        start_time = time.perf_counter()
        
        try:
            # Use provided API key or configured one
            effective_api_key = api_key or config.api_key
            
            # Prepare LiteLLM kwargs
            kwargs = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            
            # Add API key if provided
            if effective_api_key:
                kwargs["api_key"] = effective_api_key
            
            # Add custom base URL if configured
            if config.base_url:
                kwargs["api_base"] = config.base_url
            
            # Make the API call
            response = await litellm.acompletion(**kwargs)
            
            # Calculate metrics
            latency = round(time.perf_counter() - start_time, 2)
            content = response.choices[0].message.content
            
            # Extract token usage (varies by provider)
            usage = response.usage
            if usage:
                tokens_used = usage.total_tokens if hasattr(usage, 'total_tokens') else usage.prompt_tokens + usage.completion_tokens
            else:
                # Fallback: estimate tokens (rough approximation)
                tokens_used = len(content.split()) * 1.3  # Rough estimate
            
            cost = self._calculate_cost(model, tokens_used)
            self.total_cost += cost
            self.request_count += 1
            
            return LLMResponse(
                content=content,
                model=model,
                tokens_used=int(tokens_used),
                latency=latency,
                cost=cost,
                provider=provider,
                error=None
            )
            
        except Exception as e:
            latency = round(time.perf_counter() - start_time, 2)
            error_msg = str(e)
            
            # Common error handling
            if "rate limit" in error_msg.lower():
                error_msg = "Rate limit exceeded. Please try again later."
            elif "api key" in error_msg.lower():
                error_msg = "Invalid API key. Please check your credentials."
            elif "insufficient" in error_msg.lower():
                error_msg = "Insufficient quota. Please check your billing."
            
            return LLMResponse(
                content="",
                model=model,
                tokens_used=0,
                latency=latency,
                cost=0.0,
                provider=provider,
                error=error_msg
            )
    
    async def call_with_system_prompt(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.7,
        api_key: str = None
    ) -> LLMResponse:
        """
        Convenience method for system + user prompt pattern
        """
        messages = []
        if system_prompt.strip():
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        
        return await self.call_llm(
            model=model,
            messages=messages,
            temperature=temperature,
            api_key=api_key
        )
    
    def get_usage_stats(self) -> Dict:
        """Get current usage statistics"""
        return {
            "total_cost": round(self.total_cost, 4),
            "request_count": self.request_count,
            "average_cost_per_request": round(self.total_cost / max(1, self.request_count), 4)
        }
    
    def get_available_models(self) -> list:
        """Get list of available models"""
        return llm_config.get_available_models()


# Global LLM client instance
llm_client = LLMClient()
