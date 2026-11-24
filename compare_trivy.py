import argparse, json
from collections import Counter
from pathlib import Path

def count(path):
    data = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    if not isinstance(data.get('Results'), list):
        raise ValueError('Missing Results in Trivy report')
    return Counter(v.get('Severity','UNKNOWN') for r in data['Results'] for v in (r.get('Vulnerabilities') or []))
if __name__ == '__main__':
    p=argparse.ArgumentParser(); p.add_argument('before'); p.add_argument('after'); a=p.parse_args()
    b,c=count(a.before),count(a.after)
    print('Severity     Before    After    Change')
    for k in ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN']:
        print(f'{k:12} {b[k]:6} {c[k]:8} {c[k]-b[k]:8}')
