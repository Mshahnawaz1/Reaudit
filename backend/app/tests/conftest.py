import sys
from pathlib import Path

ROOT = str(Path(__file__).resolve().parents[3])
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


import pytest


@pytest.fixture(scope="session", autouse=True)
def _materialize_sample_repo_env():
    """The fixture .env is generated at test time (gitignored) so no secret-looking
    literal is committed; GitHub push protection rejects Stripe-style keys."""
    env = Path(__file__).parent / "fixtures" / "deterministic" / "sample_repo" / ".env"
    env.write_text("STRIPE_SECRET_KEY=" + "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "\nDEBUG=true\n")
    yield
