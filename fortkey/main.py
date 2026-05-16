#!/usr/bin/env python3
"""FortKey desktop entry point."""

from gui import FortKeyApp


def main() -> None:
    app = FortKeyApp()
    app.mainloop()


if __name__ == "__main__":
    main()
