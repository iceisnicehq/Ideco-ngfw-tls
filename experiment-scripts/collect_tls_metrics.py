#!/usr/bin/env python3
"""
Сбор метрик TLS-рукопожатия через curl -w (Ideco NGFW или любой Linux-клиент с curl).

Метрика: tls_handshake_s = time_appconnect - time_connect (секунды).
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
import time
from datetime import datetime, timezone

CSV_COLUMNS = [
    "run_index",
    "timestamp_iso",
    "url",
    "chain",
    "compression",
    "delay_ms",
    "time_namelookup",
    "time_connect",
    "time_appconnect",
    "time_total",
    "tls_handshake_s",
    "tls_handshake_ms",
    "curl_exit_code",
]


def parse_float(s: str) -> float:
    s = (s or "").strip()
    return float(s) if s else float("nan")


def run_one_curl(url: str, insecure: bool) -> tuple[list[float], int, str]:
    fmt = "%{time_namelookup},%{time_connect},%{time_appconnect},%{time_total}"
    cmd = ["curl", "-sS", "-o", "/dev/null", "-w", fmt]
    if insecure:
        cmd.append("-k")
    cmd.append(url)

    proc = subprocess.run(cmd, capture_output=True, text=True)
    err = proc.stderr.strip()

    line = proc.stdout.strip()
    parts = line.split(",")
    while len(parts) < 4:
        parts.append("")
    tn, tc, ta, tt = (parse_float(parts[i]) for i in range(4))
    vals = [tn, tc, ta, tt]
    tls_s = ta - tc if tc == tc and ta == ta else float("nan")
    return vals + [tls_s], proc.returncode, err


def main() -> int:
    p = argparse.ArgumentParser(description="Сбор серии замеров TLS (curl time_appconnect - time_connect)")
    p.add_argument("--url", required=True, help="HTTPS URL для curl")
    p.add_argument("--runs", type=int, default=250, help="Число повторов (по умолчанию 250)")
    p.add_argument("--sleep-ms", type=int, default=150, help="Пауза между запросами, мс")
    p.add_argument("--output", "-o", required=True, help="Выходной CSV")
    p.add_argument("--stderr-log", help="Файл для объединённого stderr curl")
    p.add_argument("--chain", default="unknown", help="Метка уровня цепочки: small|medium|large|...")
    p.add_argument(
        "--compression",
        default="unknown",
        help="Метка режима сервера: off (без -cert_comp) или zlib (на VPS включён -cert_comp)",
    )
    p.add_argument("--delay-ms", type=int, default=-1, help="Метка задержки сети (0, 50); -1 = не указано")
    p.add_argument("--insecure-k", action="store_true", help="curl -k (самоподписанные сертификаты)")
    args = p.parse_args()

    stderr_lines: list[str] = []

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()

        for i in range(1, args.runs + 1):
            ts = datetime.now(timezone.utc).isoformat()
            vals, code, cerr = run_one_curl(args.url, args.insecure_k)
            if cerr:
                print(f"run {i} stderr: {cerr}", file=sys.stderr)
                stderr_lines.append(f"=== run {i} ===\n{cerr}")
            tn, tc, ta, tt, tls_s = vals
            row = {
                "run_index": i,
                "timestamp_iso": ts,
                "url": args.url,
                "chain": args.chain,
                "compression": args.compression,
                "delay_ms": args.delay_ms,
                "time_namelookup": tn,
                "time_connect": tc,
                "time_appconnect": ta,
                "time_total": tt,
                "tls_handshake_s": tls_s,
                "tls_handshake_ms": tls_s * 1000.0 if tls_s == tls_s else float("nan"),
                "curl_exit_code": code,
            }
            w.writerow(row)
            f.flush()

            if args.sleep_ms > 0 and i < args.runs:
                time.sleep(args.sleep_ms / 1000.0)

        if args.stderr_log:
            with open(args.stderr_log, "w", encoding="utf-8") as fe:
                fe.write("\n".join(stderr_lines))

    print(f"Written {args.runs} rows to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
