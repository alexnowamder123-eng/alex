"""Compare desired Git configuration with a collected running-config; never apply changes."""
import argparse
from pathlib import Path
import difflib

def normalize(path):
    return [line.rstrip() for line in Path(path).read_text(encoding='utf-8-sig').splitlines() if line.strip() and not line.startswith(('Building configuration','Current configuration','!'))]

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('desired'); p.add_argument('running'); a = p.parse_args()
    desired, running = normalize(a.desired), normalize(a.running)
    if desired != running:
        # Do not print full config (may contain secrets).
        print('DRIFT: configuration differs; inspect securely.')
        raise SystemExit(1)
    print('NO DRIFT')
