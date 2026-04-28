#!/usr/bin/env python3
"""
Сбор метрик TLS-рукопожатия через curl -w (Ideco NGFW или любой Linux-клиент с curl).

Метрика: tls_handshake_s = time_appconnect - time_connect (секунды).
Интерактивный проход A–B–C–D: см. collect_tls_abcd.py
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

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


def collect_series(
    url: str,
    runs: int,
    sleep_ms: int,
    output: str | Path,
    chain: str,
    compression: str,
    delay_ms: int,
    insecure_k: bool,
    stderr_log: str | Path | None = None,
) -> None:
    """Пишет один CSV с серией замеров (формат совместим с analyze_tls_results.py)."""
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if stderr_log:
        Path(stderr_log).parent.mkdir(parents=True, exist_ok=True)

    stderr_lines: list[str] = []

    with open(output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()

        for i in range(1, runs + 1):
            ts = datetime.now(timezone.utc).isoformat()
            vals, code, cerr = run_one_curl(url, insecure_k)
            if cerr:
                print(f"run {i} stderr: {cerr}", file=sys.stderr)
                stderr_lines.append(f"=== run {i} ===\n{cerr}")
            tn, tc, ta, tt, tls_s = vals
            row = {
                "run_index": i,
                "timestamp_iso": ts,
                "url": url,
                "chain": chain,
                "compression": compression,
                "delay_ms": delay_ms,
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

            if sleep_ms > 0 and i < runs:
                time.sleep(sleep_ms / 1000.0)

        if stderr_log:
            with open(stderr_log, "w", encoding="utf-8") as fe:
                fe.write("\n".join(stderr_lines))


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

    collect_series(
        url=args.url,
        runs=args.runs,
        sleep_ms=args.sleep_ms,
        output=args.output,
        chain=args.chain,
        compression=args.compression,
        delay_ms=args.delay_ms,
        insecure_k=args.insecure_k,
        stderr_log=args.stderr_log,
    )

    print(f"Written {args.runs} rows to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
