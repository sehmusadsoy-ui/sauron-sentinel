"""Windowed executable entry point; optional GUI dependencies load only in main."""

from sauron_sentinel.desktop import main

if __name__ == "__main__":
    raise SystemExit(main())
