#!/usr/bin/env python3
"""从 fpprobe 的 visits.jsonl 生成 ssfp 的 [ja4] 对照表。

用法: python3 -I ja4_table.py visits.jsonl [--min 2]
只收录"同一个 JA4 只对应一种浏览器自报 OS"且出现次数 >= --min 的条目；
冲突的 JA4（例如 Chrome 在 Windows 和 Linux 上相同）列在注释里，不写入表。
"""
import json
import sys
from collections import Counter, defaultdict


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    path = args[0]
    min_count = int(args[args.index("--min") + 1]) if "--min" in args else 2
    seen = defaultdict(Counter)
    for line in open(path, encoding="utf-8"):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        ja4 = (r.get("tls") or {}).get("ja4")
        fam = (r.get("os_http") or {}).get("family")
        if ja4 and fam in ("windows", "apple", "linux"):
            seen[ja4][fam] += 1
    print("[ja4]")
    conflicts = []
    for ja4, fams in sorted(seen.items()):
        if len(fams) == 1:
            fam, n = next(iter(fams.items()))
            if n >= min_count:
                print(f'"{ja4}" = "{fam}"  # {n} 次')
        else:
            conflicts.append((ja4, fams))
    for ja4, fams in conflicts:
        print(f"# 冲突，未收录: {ja4} {dict(fams)}")


if __name__ == "__main__":
    main()
