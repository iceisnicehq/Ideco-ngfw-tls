#!/usr/bin/env python3
"""
Извлечение длительности TLS 1.3 рукопожатия из pcap (tshark).

Метрика по умолчанию: время от первого TCP SYN клиента (на порт 443) до первого
TLS Application Data (record content type 23) от пира с ip.src != client_ip
в том же tcp.stream. Требуется tshark (Wireshark).

Выходной CSV совместим с analyze_tls_results.py (колонки chain, compression,
delay_ms, tls_handshake_ms и пр.).
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Совместимость с collect_tls_metrics / analyze_tls_results
OUT_COLUMNS = [
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
    "source_client",
    "phase_id",
    "tcp_stream",
]


def _run_tshark_fields(
    pcap: Path,
    *,
    appdata_field: str,
) -> list[list[str]]:
    cmd = [
        "tshark",
        "-r",
        str(pcap),
        "-Y",
        "tcp.port == 443",
        "-T",
        "fields",
        "-e",
        "frame.time_epoch",
        "-e",
        "tcp.stream",
        "-e",
        "ip.src",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "tcp.flags.syn",
        "-e",
        "tcp.flags.ack",
        "-e",
        appdata_field,
        "-E",
        "separator=|",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(
            f"tshark failed (rc={r.returncode}): {r.stderr.strip() or r.stdout.strip()}"
        )
    lines = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        lines.append(line.split("|"))
    return lines


def handshake_rows_from_tshark(
    pcap: Path,
    client_ip: str,
    *,
    appdata_field: str = "tls.record.content_type",
) -> list[tuple[int, float, float]]:
    """
    Returns list of (tcp_stream, t_syn_epoch, delta_ms).
    """
    raw = _run_tshark_fields(pcap, appdata_field=appdata_field)
    if not raw:
        return []

    syn_time: dict[int, float] = {}
    appdata_time: dict[int, float] = {}

    for parts in raw:
        if len(parts) < 8:
            parts.extend([""] * (8 - len(parts)))
        try:
            t = float(parts[0])
            stream = int(parts[1])
            ip_src = parts[2].strip()
            srcport = parts[3].strip()
            dstport = parts[4].strip()
            syn = parts[5].strip() in ("1", "True", "true")
            ack = parts[6].strip() in ("1", "True", "true")
            ctype = parts[7].strip()
        except (ValueError, IndexError):
            continue

        if dstport == "443" and syn and not ack and ip_src == client_ip:
            if stream not in syn_time:
                syn_time[stream] = t

        if srcport == "443" and ip_src != client_ip and ctype == "23":
            if stream not in appdata_time:
                appdata_time[stream] = t

    out: list[tuple[int, float, float]] = []
    for stream, t0 in sorted(syn_time.items()):
        t1 = appdata_time.get(stream)
        if t1 is None or t1 < t0:
            continue
        out.append((stream, t0, (t1 - t0) * 1000.0))
    return out


def probe_appdata_field(pcap: Path) -> str:
    for field in ("tls.record.content_type", "ssl.record.content_type"):
        r = subprocess.run(
            [
                "tshark",
                "-r",
                str(pcap),
                "-Y",
                f"tcp.port==443 && {field}==23",
                "-c",
                "1",
            ],
            capture_output=True,
            text=True,
        )
        if r.returncode == 0 and (r.stdout or "").strip():
            return field
    return "tls.record.content_type"


def main() -> int:
    ap = argparse.ArgumentParser(description="PCAP → CSV длительностей TLS handshakes (tshark)")
    ap.add_argument("pcap", type=Path, help="Файл .pcap/.pcapng")
    ap.add_argument("--client-ip", required=True, help="IP хоста, где снят дамп (исходящий SYN)")
    ap.add_argument("--chain", default="small", help="Метка цепочки (small/medium/large)")
    ap.add_argument("--compression", default="off", help="off или zlib")
    ap.add_argument("--delay-ms", type=int, default=0)
    ap.add_argument("--source-client", default="", help="Имя клиента / id")
    ap.add_argument("--phase-id", default="", help="Идентификатор фазы прогона")
    ap.add_argument("--wrk-url", default="https://ideco.local/", help="Колонка url в CSV")
    ap.add_argument(
        "--appdata-field",
        default="",
        help="Поле tshark для типа записи TLS (23=app data); пусто=авто",
    )
    ap.add_argument("-o", "--output", type=Path, required=True, help="Выходной CSV")
    ap.add_argument(
        "--probe-only",
        action="store_true",
        help="Только напечатать выбранное поле appdata и выйти",
    )
    args = ap.parse_args()

    pcap = args.pcap.expanduser().resolve()
    if not pcap.is_file():
        print(f"Not found: {pcap}", file=sys.stderr)
        return 1

    field = args.appdata_field.strip() or probe_appdata_field(pcap)
    if args.probe_only:
        print(field)
        return 0

    tuples = handshake_rows_from_tshark(pcap, args.client_ip, appdata_field=field)
    args.output.parent.mkdir(parents=True, exist_ok=True)

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=OUT_COLUMNS, extrasaction="ignore")
        w.writeheader()
        for i, (stream, t0, ms) in enumerate(tuples):
            iso = datetime.fromtimestamp(t0, tz=timezone.utc).isoformat()
            s = ms / 1000.0
            w.writerow(
                {
                    "run_index": i,
                    "timestamp_iso": iso,
                    "url": args.wrk_url,
                    "chain": args.chain,
                    "compression": args.compression,
                    "delay_ms": args.delay_ms,
                    "time_namelookup": "",
                    "time_connect": "",
                    "time_appconnect": "",
                    "time_total": "",
                    "tls_handshake_s": f"{s:.6f}",
                    "tls_handshake_ms": f"{ms:.3f}",
                    "curl_exit_code": "",
                    "source_client": args.source_client,
                    "phase_id": args.phase_id,
                    "tcp_stream": stream,
                }
            )

    print(f"Written {len(tuples)} rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
