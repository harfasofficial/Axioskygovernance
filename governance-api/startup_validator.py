# startup_validator.py
"""
Run at application startup to verify all required secrets and config
are present and have sufficient entropy. Crashes fast with a clear
error message rather than running with insecure defaults.
"""
import os
import sys
import secrets

REQUIRED_SECRETS = [
    "SECRET_KEY",
    "WEBHOOK_SECRET",
    "DB_PASSWORD",
]

KNOWN_WEAK_VALUES = {
    "dev-secret-key-change-in-production",
    "dev-webhook-secret-change-in-production",
    "axiosky",
    "changeme",
    "secret",
    "password",
    "",
}

MIN_SECRET_LENGTH = 32


def validate_secrets():
    """
    Called once at startup. Aborts with sys.exit(1) if any secret is
    missing, too short, or set to a known-weak default value.

    Only enforced in production environment.
    """
    env = os.getenv("ENVIRONMENT", "development").lower()
    if env not in ("production",):
        return  # Only enforce in production

    errors = []

    for key in REQUIRED_SECRETS:
        value = os.getenv(key, "")

        if not value:
            errors.append(f"  MISSING: {key} is not set")
            continue

        if value.lower() in KNOWN_WEAK_VALUES:
            errors.append(f"  WEAK: {key} is set to a known-weak default value")
            continue

        if len(value) < MIN_SECRET_LENGTH:
            errors.append(
                f"  SHORT: {key} is only {len(value)} chars (minimum {MIN_SECRET_LENGTH})"
            )

    if errors:
        print(
            "\n" + "=" * 60 + "\n"
            "STARTUP ABORTED -- INSECURE CONFIGURATION\n"
            + "=" * 60 + "\n"
            + "\n".join(errors)
            + "\n\nTo generate a strong secret key, run:\n"
            "  python -c \"import secrets; print(secrets.token_hex(32))\"\n"
            + "=" * 60 + "\n",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    validate_secrets()
    print("All secrets validated OK.")
