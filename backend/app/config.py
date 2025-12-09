from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "sqlite:///./data/networkmapper.db"

    # Security
    SECRET_KEY: str = "your-secret-key-here-please-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS
    ALLOW_ORIGINS: str = "http://localhost:3000"

    # Scanning
    DEFAULT_SCAN_TIMEOUT: int = 300
    MAX_CONCURRENT_SCANS: int = 3
    ENABLE_ARP_SCAN: bool = True
    ENABLE_ICMP_SCAN: bool = True
    ENABLE_NMAP_DISCOVERY: bool = True

    # Application
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    @property
    def allow_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.ALLOW_ORIGINS.split(",")]

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
