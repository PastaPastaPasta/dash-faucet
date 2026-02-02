from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Dash Core RPC settings
    dash_rpc_user: str = "dashrpc"
    dash_rpc_password: str = "password"
    dash_rpc_host: str = "localhost"
    dash_rpc_port: int = 19998  # Testnet RPC port

    # Rate limiting
    rate_limit_per_hour: int = 3

    # Credit amount in duffs (1 DASH = 100,000,000 duffs)
    credit_amount: int = 100_000_000  # 1 DASH

    # Core faucet amount in DASH
    core_faucet_amount: float = 1.0  # 1 DASH per request

    # InstantLock timeout in seconds
    islock_timeout: int = 30
    islock_poll_interval: float = 1.0

    # Transaction fee in duffs
    tx_fee: int = 10_000  # 0.0001 DASH

    # CAP captcha settings
    cap_api_endpoint: str = "http://localhost:3000"  # Public endpoint for frontend
    cap_internal_endpoint: str = "http://cap:3000"   # Internal endpoint for backend verification
    cap_site_key: str = ""
    cap_secret: str = ""

    # Hard CAP for rate limit bypass (higher difficulty)
    cap_hard_site_key: str = ""
    cap_hard_secret: str = ""

    # Promo codes config file path
    promo_codes_file: str = "promo_codes.json"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
