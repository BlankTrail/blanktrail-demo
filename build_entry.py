"""PyInstaller entry point for blanktrail-demo.exe. Not part of the app.

`blanktrail_demo/__main__.py` (the entry point for `python -m blanktrail_demo`)
imports its `main` with `from .cli import main` — a relative import, which
needs package context. PyInstaller's frozen bootstrap runs whatever script it
is pointed at as a bare top-level `__main__` module with no such context, so
pointing it at `__main__.py` directly fails with "attempted relative import
with no known parent package".

This script exists only to give PyInstaller an entry point that imports the
same `main` with an absolute import instead, which needs no package context
and works identically frozen or not. It is invoked solely by
build-windows.ps1 and is never imported by, or shipped inside, the installed
package.
"""

from blanktrail_demo.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
