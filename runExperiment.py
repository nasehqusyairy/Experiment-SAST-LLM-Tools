"""Backward-compatible entry point for the persistent experiment manager.

The previous script contained an invalidly indented module, embedded prompts, and
an unconditional directory runner. All new runs must select a scenario and sample
through the safe manager interface.
"""
from experiment_manager import main


if __name__ == "__main__":
    raise SystemExit(main())
