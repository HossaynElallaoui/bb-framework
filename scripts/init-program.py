"""Create a program workspace from the checked-in template."""

import argparse
import re
import shutil
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="Lowercase program slug, e.g. example-program")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", args.name):
        parser.error("Use lowercase letters, numbers, and single separating hyphens.")

    root = Path(__file__).resolve().parent.parent
    destination = root / "programs" / args.name
    if destination.exists():
        parser.error(f"Workspace already exists: {destination}")
    shutil.copytree(root / "programs" / "_template", destination)
    print(f"Created {destination}")
    print(f"Next: fill in {destination / 'scope.md'}")


if __name__ == "__main__":
    main()
