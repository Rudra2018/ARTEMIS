"""
Configuration module for AI Chatbot Testing Suite
Handles API keys, endpoints, and test configurations
"""

import os
from typing import Dict, Optional
from dataclasses import dataclass
from enum import Enum
import json

class AIProvider(Enum):
    OPENAI = "openai"
    META_AI = "meta_ai"
    GOOGLE_AI_STUDIO = "google_ai_studio"
    CLAUDE = "claude"
    HUGGINGFACE = "huggingface"
    COHERE = "cohere"
    AZURE_OPENAI = "azure_openai"
    AWS_BEDROCK = "aws_bedrock"
    PALM_API = "palm_api"
    VERTEX_AI = "vertex_ai"

@dataclass
class APIConfig:
    """Configuration for AI provider APIs"""
    provider: AIProvider
    api_key: str
    base_url: str
    model: str
    timeout: int = 30
    max_retries: int = 3
    rate_limit_rpm: int = 60
    headers: Optional[Dict[str, str]] = None
    additional_params: Optional[Dict[str, any]] = None

@dataclass
class TestConfig:
    """General test configuration"""
    run_live_tests: bool = False  # Set to True to run against real APIs
    mock_responses: bool = True   # Use mock responses by default
    max_test_duration: int = 300  # Maximum test duration in seconds
    concurrent_test_limit: int = 10  # Maximum concurrent tests
    output_dir: str = "test_results"
    log_level: str = "INFO"
    generate_reports: bool = True

class ConfigManager:
    """Manages configuration for the AI testing suite"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or "test_config.json"
        self.api_configs = self._load_api_configs()
        self.test_config = self._load_test_config()
    
    def _load_api_configs(self) -> Dict[AIProvider, APIConfig]:
        """Load API configurations from environment variables and config file"""
        configs = {}
        
        # OpenAI Configuration
        if os.getenv('OPENAI_API_KEY'):
            configs[AIProvider.OPENAI] = APIConfig(
                provider=AIProvider.OPENAI,
                api_key=os.getenv('OPENAI_API_KEY'),
                base_url="https://api.openai.com/v1",
                model="gpt-3.5-turbo",
                rate_limit_rpm=3500,
                headers={
                    "Authorization": f"Bearer {os.getenv('OPENAI_API_KEY')}",
                    "Content-Type": "application/json"
                }
            )
        
        # Claude Configuration
        if os.getenv('CLAUDE_API_KEY'):
            configs[AIProvider.CLAUDE] = APIConfig(
                provider=AIProvider.CLAUDE,
                api_key=os.getenv('CLAUDE_API_KEY'),
                base_url="https://api.anthropic.com/v1",
                model="claude-3-haiku-20240307",
                rate_limit_rpm=100,
                headers={
                    "x-api-key": os.getenv('CLAUDE_API_KEY'),
                    "Content-Type": "application/json",
                    "anthropic-version": "2023-06-01"
                }
            )
        
        # Google AI Studio Configuration
        if os.getenv('GOOGLE_AI_STUDIO_API_KEY'):
            configs[AIProvider.GOOGLE_AI_STUDIO] = APIConfig(
                provider=AIProvider.GOOGLE_AI_STUDIO,
                api_key=os.getenv('GOOGLE_AI_STUDIO_API_KEY'),
                base_url="https://generativelanguage.googleapis.com/v1",
                model="gemini-pro",
                rate_limit_rpm=60,
                headers={
                    "Content-Type": "application/json"
                }
            )
        
        # Meta AI Configuration (hypothetical)
        if os.getenv('META_AI_API_KEY'):
            configs[AIProvider.META_AI] = APIConfig(
                provider=AIProvider.META_AI,
                api_key=os.getenv('META_AI_API_KEY'),
                base_url="https://api.meta.ai/v1",
                model="llama-2-70b-chat",
                rate_limit_rpm=1000,
                headers={
                    "Authorization": f"Bearer {os.getenv('META_AI_API_KEY')}",
                    "Content-Type": "application/json"
                }
            )
        
        # Hugging Face Configuration
        if os.getenv('HUGGINGFACE_API_KEY'):
            configs[AIProvider.HUGGINGFACE] = APIConfig(
                provider=AIProvider.HUGGINGFACE,
                api_key=os.getenv('HUGGINGFACE_API_KEY'),
                base_url="https://api-inference.huggingface.co/models",
                model="microsoft/DialoGPT-medium",
                rate_limit_rpm=1000,
                headers={
                    "Authorization": f"Bearer {os.getenv('HUGGINGFACE_API_KEY')}",
                    "Content-Type": "application/json"
                }
            )
        
        # Cohere Configuration
        if os.getenv('COHERE_API_KEY'):
            configs[AIProvider.COHERE] = APIConfig(
                provider=AIProvider.COHERE,
                api_key=os.getenv('COHERE_API_KEY'),
                base_url="https://api.cohere.ai/v1",
                model="command",
                rate_limit_rpm=100,
                headers={
                    "Authorization": f"Bearer {os.getenv('COHERE_API_KEY')}",
                    "Content-Type": "application/json"
                }
            )
        
        # Azure OpenAI Configuration
        if os.getenv('AZURE_OPENAI_API_KEY') and os.getenv('AZURE_OPENAI_ENDPOINT'):
            configs[AIProvider.AZURE_OPENAI] = APIConfig(
                provider=AIProvider.AZURE_OPENAI,
                api_key=os.getenv('AZURE_OPENAI_API_KEY'),
                base_url=os.getenv('AZURE_OPENAI_ENDPOINT'),
                model="gpt-35-turbo",
                rate_limit_rpm=240,
                headers={
                    "api-key": os.getenv('AZURE_OPENAI_API_KEY'),
                    "Content-Type": "application/json"
                },
                additional_params={
                    "api_version": "2023-12-01-preview"
                }
            )
        
        # Load additional configs from file if exists
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                file_config = json.load(f)
                # Merge file configs with environment configs
                # File configs override environment configs
                for provider_name, config_data in file_config.get('api_configs', {}).items():
                    try:
                        provider = AIProvider(provider_name)
                        configs[provider] = APIConfig(**config_data)
                    except ValueError:
                        print(f"Unknown provider in config file: {provider_name}")
        
        return configs
    
    def _load_test_config(self) -> TestConfig:
        """Load test configuration"""
        test_config = TestConfig()
        
        # Override from environment variables
        test_config.run_live_tests = os.getenv('RUN_LIVE_TESTS', 'false').lower() == 'true'
        test_config.mock_responses = os.getenv('MOCK_RESPONSES', 'true').lower() == 'true'
        test_config.max_test_duration = int(os.getenv('MAX_TEST_DURATION', '300'))
        test_config.concurrent_test_limit = int(os.getenv('CONCURRENT_TEST_LIMIT', '10'))
        test_config.output_dir = os.getenv('TEST_OUTPUT_DIR', 'test_results')
        test_config.log_level = os.getenv('LOG_LEVEL', 'INFO')
        test_config.generate_reports = os.getenv('GENERATE_REPORTS', 'true').lower() == 'true'
        
        # Override from config file
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                file_config = json.load(f)
                test_config_data = file_config.get('test_config', {})
                for key, value in test_config_data.items():
                    if hasattr(test_config, key):
                        setattr(test_config, key, value)
        
        return test_config
    
    def get_api_config(self, provider: AIProvider) -> Optional[APIConfig]:
        """Get API configuration for a specific provider"""
        return self.api_configs.get(provider)
    
    def get_available_providers(self) -> list[AIProvider]:
        """Get list of available providers with valid configurations"""
        return list(self.api_configs.keys())
    
    def is_provider_configured(self, provider: AIProvider) -> bool:
        """Check if a provider is properly configured"""
        return provider in self.api_configs
    
    def save_config_template(self, filename: str = "test_config_template.json"):
        """Save a configuration template file"""
        template = {
            "api_configs": {
                "openai": {
                    "provider": "openai",
                    "api_key": "your-openai-api-key",
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-3.5-turbo",
                    "timeout": 30,
                    "max_retries": 3,
                    "rate_limit_rpm": 3500,
                    "headers": {
                        "Authorization": "Bearer your-openai-api-key",
                        "Content-Type": "application/json"
                    }
                },
                "claude": {
                    "provider": "claude",
                    "api_key": "your-claude-api-key",
                    "base_url": "https://api.anthropic.com/v1",
                    "model": "claude-3-haiku-20240307",
                    "timeout": 30,
                    "max_retries": 3,
                    "rate_limit_rpm": 100,
                    "headers": {
                        "x-api-key": "your-claude-api-key",
                        "Content-Type": "application/json",
                        "anthropic-version": "2023-06-01"
                    }
                }
            },
            "test_config": {
                "run_live_tests": False,
                "mock_responses": True,
                "max_test_duration": 300,
                "concurrent_test_limit": 10,
                "output_dir": "test_results",
                "log_level": "INFO",
                "generate_reports": True
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(template, f, indent=2)
        
        print(f"Configuration template saved to {filename}")
    
    def validate_configuration(self) -> Dict[str, any]:
        """Validate the current configuration"""
        validation_results = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "configured_providers": len(self.api_configs),
            "provider_details": {}
        }
        
        # Check if at least one provider is configured
        if not self.api_configs:
            validation_results["valid"] = False
            validation_results["errors"].append("No API providers configured")
        
        # Validate each provider configuration
        for provider, config in self.api_configs.items():
            provider_validation = {
                "valid": True,
                "errors": [],
                "warnings": []
            }
            
            # Check required fields
            if not config.api_key or config.api_key == "your-api-key":
                provider_validation["valid"] = False
                provider_validation["errors"].append("Invalid or missing API key")
            
            if not config.base_url:
                provider_validation["valid"] = False
                provider_validation["errors"].append("Missing base URL")
            
            if not config.model:
                provider_validation["warnings"].append("No model specified")
            
            # Check rate limits
            if config.rate_limit_rpm <= 0:
                provider_validation["warnings"].append("Rate limit not specified or invalid")
            
            validation_results["provider_details"][provider.value] = provider_validation
            
            if not provider_validation["valid"]:
                validation_results["valid"] = False
        
        # Validate test configuration
        if self.test_config.max_test_duration <= 0:
            validation_results["warnings"].append("Invalid max test duration")
        
        if self.test_config.concurrent_test_limit <= 0:
            validation_results["warnings"].append("Invalid concurrent test limit")
        
        return validation_results

# Global configuration instance
config_manager = ConfigManager()

def get_config() -> ConfigManager:
    """Get the global configuration manager instance"""
    return config_manager

def setup_environment():
    """Setup environment for testing"""
    # Create output directory
    os.makedirs(config_manager.test_config.output_dir, exist_ok=True)
    
    # Validate configuration
    validation = config_manager.validate_configuration()
    
    if not validation["valid"]:
        print("⚠️  Configuration validation failed:")
        for error in validation["errors"]:
            print(f"   ❌ {error}")
    
    if validation["warnings"]:
        print("⚠️  Configuration warnings:")
        for warning in validation["warnings"]:
            print(f"   ⚠️  {warning}")
    
    print(f"✅ Configuration loaded: {validation['configured_providers']} providers configured")
    
    return validation["valid"]

if __name__ == "__main__":
    # Setup environment and validate configuration
    is_valid = setup_environment()
    
    # Save configuration template
    config_manager.save_config_template()
    
    # Print available providers
    providers = config_manager.get_available_providers()
    print(f"\nAvailable providers: {[p.value for p in providers]}")
    
    # Print detailed validation results
    validation = config_manager.validate_configuration()
    print(f"\nValidation results: {validation}")