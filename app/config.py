from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    mongodb_uri: str = ""
    admin_username: str = "admin"
    admin_password: str = ""
    session_secret: str = ""
    cors_origins: str = "http://localhost:3000,http://localhost:8000"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


settings = Settings()
