
import hashlib
import json
import sys
from pathlib import Path

ALGO_LIST = ['sha256', 'sha1', 'md5']

def compute_hash(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def create_hashes(path: Path, out_json: Path):
    result = {'file': str(path.name), 'hashes': {}}
    for algo in ALGO_LIST:
        result['hashes'][algo] = compute_hash(path, algo)
    with open(out_json, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"[+] Wrote hashes to {out_json}")

def check_hashes(path: Path, hashes_json: Path):
    if not hashes_json.exists():
        print(f"[-] Hash file {hashes_json} not found")
        return 2
    data = json.load(open(hashes_json))
    old = data.get('hashes', {})
    ok = True
    print(f"Checking integrity for {path} using {hashes_json}\n")
    for algo in ALGO_LIST:
        expected = old.get(algo)
        actual = compute_hash(path, algo)
        if expected is None:
            print(f"[!] No {algo} in {hashes_json}")
            ok = False
            continue
        if expected.lower() == actual.lower():
            print(f"[OK]   {algo}: {actual}")
        else:
            print(f"[FAIL] {algo}: expected {expected}, actual {actual}")
            ok = False
    print("\nOverall integrity:", "PASS" if ok else "FAIL")
    return 0 if ok else 1

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python hash_util.py create <file>")
        print("  python hash_util.py check <file> <hashes.json>")
        sys.exit(2)

    cmd = sys.argv[1].lower()
    if cmd == 'create':
        f = Path(sys.argv[2])
        out_json = f.parent / 'hashes.json'
        create_hashes(f, out_json)
    elif cmd == 'check':
        f = Path(sys.argv[2])
        j = Path(sys.argv[3])
        check_hashes(f, j)
    else:
        print("Unknown command")
