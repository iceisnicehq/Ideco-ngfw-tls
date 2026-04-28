#!/usr/bin/env python3
"""
Интерактивный сбор метрик для режимов A, B, C, D подряд (одна цепочка на запуск).

Подразумевается: вы настраиваете VPS (s_server и tc) между режимами; скрипт только шлёт curl
и ждёт Enter перед следующим режимом после записи CSV.

Режимы (метки как в eksperiment-rfc8879-vps-ideco-guide.md):
  A — без -cert_comp, без tc (delay_ms=0)
  B — с -cert_comp, без tc (delay_ms=0)
  C — без -cert_comp, tc 50 ms (delay_ms=50)
  D — с -cert_comp, tc 50 ms (delay_ms=50)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from collect_tls_metrics import collect_series


def phase_csv_name(chain: str, letter: str, compression: str, delay_ms: int) -> str:
    return f"{chain}_{letter}_{compression}_delay{delay_ms}.csv"


def main() -> int:
    p = argparse.ArgumentParser(
        description="Сбор TLS-метрик по режимам A→B→C→D с паузой Enter между режимами"
    )
    p.add_argument("--url", required=True, help="HTTPS URL (curl)")
    p.add_argument(
        "--chain",
        required=True,
        choices=("small", "medium", "large"),
        help="Уровень цепочки на VPS (метка в CSV и префикс файлов)",
    )
    p.add_argument("--runs", type=int, default=100, help="Запросов на режим (по умолчанию 100)")
    p.add_argument("--sleep-ms", type=int, default=100, help="Пауза между запросами, мс (по умолчанию 100)")
    p.add_argument(
        "--output-dir",
        "-d",
        default="../runs",
        help="Каталог для CSV (создаётся при необходимости)",
    )
    p.add_argument("--insecure-k", action="store_true", help="curl -k")
    p.add_argument(
        "--yes",
        action="store_true",
        help="Не ждать Enter между режимами (для отладки; VPS должен совпадать со всеми режимами сам)",
    )
    args = p.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    phases: list[tuple[str, str, int, str]] = [
        ("A", "off", 0, "На VPS: s_server без -cert_comp; tc выключен (tc qdisc del … при необходимости)."),
        ("B", "zlib", 0, "На VPS: s_server с -cert_comp; tc выключен."),
        ("C", "off", 50, "На VPS: s_server без -cert_comp; включён tc netem delay 50 ms."),
        ("D", "zlib", 50, "На VPS: s_server с -cert_comp; включён tc netem delay 50 ms."),
    ]

    print(
        f"Цепочка: {args.chain} | запросов на режим: {args.runs} | пауза: {args.sleep_ms} мс\n"
        f"Каталог: {out_dir.resolve()}\n"
        "Перед стартом подготовьте VPS для режима A — первые замеры начнутся сразу.\n",
        file=sys.stderr,
    )

    for idx, (letter, compression, delay_ms, hint) in enumerate(phases):
        csv_name = phase_csv_name(args.chain, letter, compression, delay_ms)
        out_path = out_dir / csv_name
        err_path = out_dir / (Path(csv_name).stem + ".err.log")

        print(f"\n>>> Режим {letter}: {hint}", file=sys.stderr)
        print(f"    → файл: {out_path}", file=sys.stderr)

        if idx > 0 and not args.yes:
            print("    После переключения VPS нажмите Enter, чтобы начать замеры…", file=sys.stderr)
            try:
                input()
            except EOFError:
                print("Нет stdin — завершение.", file=sys.stderr)
                return 1

        collect_series(
            url=args.url,
            runs=args.runs,
            sleep_ms=args.sleep_ms,
            output=out_path,
            chain=args.chain,
            compression=compression,
            delay_ms=delay_ms,
            insecure_k=args.insecure_k,
            stderr_log=err_path,
        )
        print(f"Written {args.runs} rows → {out_path}", file=sys.stderr)

    print("\nВсе четыре режима (A–D) записаны.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
