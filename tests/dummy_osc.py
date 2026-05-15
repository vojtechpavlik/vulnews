#!/usr/bin/env python3
"""Dummy osc command for testing. Mimics osc subcommands with canned output."""

import os
import sys

SEARCH_RESULTS = """\
openSUSE:Factory|nodejs-evil-package
devel:languages:nodejs|nodejs-evil-package
"""

SEARCH_WITH_DISCONTINUED = """\
openSUSE:Factory|nodejs-evil-package
DISCONTINUED:openSUSE:13.2|nodejs-evil-package
devel:languages:nodejs|nodejs-evil-package
"""

LOG_XML = """\
<?xml version="1.0"?>
<log>
  <logentry revision="3">
    <author>maintainer</author>
    <date>2025-01-10 12:00:00</date>
    <msg>Update to version 1.0.4</msg>
  </logentry>
  <logentry revision="2">
    <author>maintainer</author>
    <date>2024-12-01 10:00:00</date>
    <msg>Update to version 1.0.3</msg>
  </logentry>
  <logentry revision="1">
    <author>bot</author>
    <date>2025-02-01 08:00:00</date>
    <msg>Initial commit</msg>
  </logentry>
</log>
"""

LS_OUTPUT = """\
nodejs-evil-package.spec
nodejs-evil-package.changes
nodejs-evil-package-1.0.4.tar.gz
index.js
postinstall.sh
"""

CHANGELOG = """\
-------------------------------------------------------------------
Fri Jan 10 12:00:00 UTC 2025 - maintainer@example.com

- Update to version 1.0.4
  * Security fixes

-------------------------------------------------------------------
Sun Dec 01 10:00:00 UTC 2024 - maintainer@example.com

- Update to version 1.0.3
"""


def main():
    if os.environ.get("DUMMY_OSC_FAIL"):
        print("simulated osc error", file=sys.stderr)
        sys.exit(1)

    args = sys.argv[1:]

    if not args:
        print("dummy_osc: no subcommand", file=sys.stderr)
        sys.exit(1)

    cmd = args[0]

    if cmd == "search":
        name = ""
        for i, a in enumerate(args):
            if a == "-e" and i + 1 < len(args):
                name = args[i + 1]
                if name == "--" and i + 2 < len(args):
                    name = args[i + 2]
                break
        if name == "notfound":
            pass  # empty output
        elif name in ("evil-package", "nodejs-evil-package"):
            print(SEARCH_WITH_DISCONTINUED, end="")
        else:
            print(f"openSUSE:Factory|{name}", end="\n")

    elif cmd == "log":
        print(LOG_XML, end="")

    elif cmd == "ls":
        print(LS_OUTPUT, end="")

    elif cmd == "cat":
        filename = args[-1] if len(args) >= 4 else ""
        if filename.endswith(".changes"):
            print(CHANGELOG, end="")
        elif filename.endswith(".spec"):
            print("Name: nodejs-evil-package")
            print("Version: 1.0.4")
            print("Release: 0")
        else:
            print(f"# dummy content for {filename}")

    else:
        print(f"dummy_osc: unknown command '{cmd}'", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
