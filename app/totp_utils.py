import base64
import pyotp
import time


def hex_seed_to_base32(hex_seed: str) -> str:
    """
    Convert 64-character hex seed to Base32 string for TOTP.

    Steps:
    1. Convert hex string to bytes
    2. Encode bytes using Base32
    3. Return as UTF-8 string
    """
    seed_bytes = bytes.fromhex(hex_seed)
    base32_seed = base64.b32encode(seed_bytes).decode("utf-8")
    return base32_seed


def generate_totp_code(hex_seed: str) -> str:
    """
    Generate the current TOTP code.

    Args:
        hex_seed (str): 64-char hex seed

    Returns:
        str: 6-digit TOTP code
    """

    # Convert hex seed -> base32
    base32_seed = hex_seed_to_base32(hex_seed)

    # Create TOTP object
    totp = pyotp.TOTP(
        base32_seed,
        digits=6,       # 6-digit codes
        interval=30,    # 30 seconds per code
        digest="sha1"   # default algorithm
    )

    # Generate current code
    return totp.now()


def get_seconds_remaining() -> int:
    """
    Return seconds remaining in the current 30-second TOTP window.
    """
    return 30 - (int(time.time()) % 30)


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify user-provided TOTP code with +/-1 window allowed.

    Args:
        hex_seed (str): 64-character hex seed
        code (str): user submitted 6-digit code
        valid_window (int): time window tolerance (default ±1 period)

    Returns:
        bool: True if valid, False otherwise
    """

    base32_seed = hex_seed_to_base32(hex_seed)

    totp = pyotp.TOTP(
        base32_seed,
        digits=6,
        interval=30,
        digest="sha1"
    )

    # verify accepts +/- valid_window periods
    return totp.verify(code, valid_window=valid_window)