#!/usr/bin/env python3
"""
Полная автоматизация цикла на машине ALT (или любой Linux с SSH и curl):

  SSH на VPS — выключить прошлый s_server, при необходимости tc, запустить openssl s_server для режима A/B/C/D;
  локально — серия curl (collect_series);
  опционально SSH на Ideco NGFW — один openssl s_client -trace в файл.

Требования:
  - безпарольный SSH с ALT на VPS и (если включён trace) на Ideco;
  - на VPS sudo без пароля для tc и запуска openssl на :443 (или вход под root по SSH);
  - пути к сертификатам и бинарнику OpenSSL на VPS совпадают с конфигом.

Ограничения:
  - Оболочка на Ideco может не дать выполнить openssl — тогда выключите run_ideco_trace в remote_config.json.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from collect_tls_metrics import collect_series

PHASES: list[tuple[str, bool, bool]] = [
    ("A", False, False),
    ("B", True, False),
    ("C", False, True),
    ("D", True, True),
]


def phase_csv_name(chain: str, letter: str, compression: str, delay_ms: int) -> str:
    return f"{chain}_{letter}_{compression}_delay{delay_ms}.csv"


def load_config(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def log(msg: str, quiet: bool) -> None:
    if not quiet:
        print(f"[{ts()}] {msg}", file=sys.stderr, flush=True)


def ssh_cmd(host: str, extra_args: list[str]) -> list[str]:
    return ["ssh", *extra_args, host]


def run_ssh_script(
    host: str,
    extra_args: list[str],
    script: str,
    dry_run: bool,
    *,
    quiet: bool,
    dump_script: bool,
    label: str,
) -> int:
    if dump_script:
        log(f"{label} — полный удалённый bash:", quiet)
        print(script.rstrip(), file=sys.stderr)
        print("---", file=sys.stderr, flush=True)
    elif not quiet:
        log(f"{label} — отправка скрипта на хост по SSH ({len(script)} байт). Полный текст: --dump-remote-scripts", quiet)

    if dry_run:
        log(f"{label} — dry-run, SSH не выполняется.", quiet)
        return 0

    cmd = ssh_cmd(host, extra_args) + ["bash", "-s"]
    log(f"{label} — локальная команда: ssh … {' '.join(shlex.quote(x) for x in extra_args)} {shlex.quote(host)} bash -s", quiet)

    r = subprocess.run(cmd, input=script.encode())
    rc = r.returncode
    log(f"{label} — код возврата SSH / удалённого bash: {rc}", quiet)
    return rc


def run_ssh_capture(host: str, extra_args: list[str], remote_cmd: str, dry_run: bool, *, quiet: bool, label: str) -> tuple[int, str]:
    quoted = shlex.quote(remote_cmd)
    log(f"{label} — ssh {host} bash -lc {quoted}", quiet)
    if dry_run:
        log(f"{label} — dry-run, вывод пустой.", quiet)
        return 0, ""

    cmd = ssh_cmd(host, extra_args) + ["bash", "-lc", remote_cmd]
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")
    rc = r.returncode
    log(f"{label} — код возврата: {rc}, символов вывода: {len(out)}", quiet)
    if not quiet and out.strip():
        preview = out.strip()[:800]
        suf = " …" if len(out.strip()) > 800 else ""
        print(f"[{ts()}] {label} — первые строки вывода:\n{preview}{suf}", file=sys.stderr, flush=True)
    return rc, out


def build_vps_script(
    vp: dict[str, Any],
    tc_iface: str | None,
    chain_file: str,
    cert_comp: bool,
    tc_delay: bool,
) -> str:
    ob = vp["openssl_bin"]
    ld = vp["ld_library_path"]
    cdir = vp["cert_dir"].rstrip("/")
    lc = vp["leaf_cert"]
    lk = vp["leaf_key"]
    cc_path = f"{cdir}/{chain_file}"

    if tc_iface:
        iface_snippet = f'TC_IFACE="{tc_iface}"'
    else:
        iface_snippet = """TC_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
if [ -z "$TC_IFACE" ]; then TC_IFACE=eth0; fi"""

    lines = [
        "set -e",
        "if [ -f /tmp/rfc8879-server.pid ]; then",
        '  kill "$(cat /tmp/rfc8879-server.pid)" 2>/dev/null || true',
        "  rm -f /tmp/rfc8879-server.pid",
        "fi",
        iface_snippet,
        'sudo tc qdisc del dev "$TC_IFACE" root netem 2>/dev/null || true',
    ]
    if tc_delay:
        lines.append('sudo tc qdisc add dev "$TC_IFACE" root netem delay 50ms')
    lines += [
        f'export LD_LIBRARY_PATH="{ld}"',
        f'cd "{cdir}"',
        f'nohup "{ob}" s_server \\',
        "  -accept 443 \\",
        f'  -cert "{cdir}/{lc}" \\',
        f'  -key "{cdir}/{lk}" \\',
        f'  -cert_chain "{cc_path}" \\',
        "  -tls1_3 \\",
    ]
    if cert_comp:
        lines.append("  -cert_comp \\")
    lines += [
        "  -www -quiet \\",
        "  </dev/null >/tmp/rfc8879-server.log 2>&1 &",
        "echo $! >/tmp/rfc8879-server.pid",
        "sleep 2",
        'echo "server PID $(cat /tmp/rfc8879-server.pid)"',
        "ss -ltnp 2>/dev/null | grep -E ':443\\b' || true",
    ]
    return "\n".join(lines) + "\n"


def vps_teardown_only(
    tc_iface: str | None,
    dry_run: bool,
    host: str,
    ssh_extra: list[str],
    *,
    quiet: bool,
    dump_script: bool,
) -> None:
    iface_snippet = (
        f'TC_IFACE="{tc_iface}"'
        if tc_iface
        else """TC_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
if [ -z "$TC_IFACE" ]; then TC_IFACE=eth0; fi"""
    )
    script = f"""set -e
if [ -f /tmp/rfc8879-server.pid ]; then
  kill "$(cat /tmp/rfc8879-server.pid)" 2>/dev/null || true
  rm -f /tmp/rfc8879-server.pid
fi
{iface_snippet}
sudo tc qdisc del dev "$TC_IFACE" root netem 2>/dev/null || true
echo teardown_ok
"""
    run_ssh_script(host, ssh_extra, script, dry_run, quiet=quiet, dump_script=dump_script, label="VPS teardown")


def ideco_trace_command(cfg: dict[str, Any]) -> str:
    hp = cfg["ideco_trace_host_port"]
    ob = cfg.get("ideco_openssl", "openssl")
    return (
        f'echo | {ob} s_client -connect {hp} -tls1_3 -trace 2>&1 '
        f'| grep -A 3 -iE "CompressedCertificate|Certificate, Length" || true'
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Оркестрация VPS + замеры с ALT + опционально trace на Ideco")
    ap.add_argument(
        "--config",
        "-c",
        type=Path,
        default=Path(__file__).resolve().parent / "remote_config.json",
        help="JSON конфиг (рядом со скриптом: remote_config.json)",
    )
    ap.add_argument("--dry-run", action="store_true", help="Не выполнять SSH и curl, только план шагов")
    ap.add_argument("--quiet", "-q", action="store_true", help="Минимум сообщений")
    ap.add_argument("--dump-remote-scripts", action="store_true", help="Печатать полный bash, уходящий на VPS")
    args = ap.parse_args()

    quiet = args.quiet
    dump = args.dump_remote_scripts

    if not args.config.exists():
        print(
            f"[{ts()}] Нет файла {args.config}. Положите рядом remote_config.json "
            "(см. ALT-LINUX-RUN.md) или укажите -c /путь/к/remote_config.json",
            file=sys.stderr,
        )
        return 1

    cfg = load_config(args.config)
    dry = bool(cfg.get("dry_run")) or args.dry_run

    vps_host = cfg["vps_ssh"]
    ssh_extra = list(cfg.get("ssh_extra_args", []))
    vp = cfg["vps"]
    tc_iface = cfg.get("tc_iface")

    url = cfg["https_url"]
    out_dir = Path(cfg.get("metrics_output_dir", "../runs"))
    runs = int(cfg.get("runs_per_phase", 100))
    sleep_ms = int(cfg.get("sleep_ms", 100))
    progress_every = int(cfg.get("curl_progress_every", 25))
    insecure_k = bool(cfg.get("insecure_k", True))

    chains = list(cfg.get("chains_to_run", ["small"]))
    ideco_host = cfg.get("ideco_ssh")
    run_trace = bool(cfg.get("run_ideco_trace")) and ideco_host

    out_dir.mkdir(parents=True, exist_ok=True)

    log("=== Запуск orchestrate_remote.py ===", quiet)
    log(f"dry_run={dry} | конфиг: {args.config.resolve()}", quiet)
    log(f"VPS SSH: {vps_host}", quiet)
    log(f"HTTPS URL (curl): {url}", quiet)
    log(f"Каталог результатов: {out_dir.resolve()}", quiet)
    n_phases = len(chains) * len(PHASES)
    log(
        f"Цепочки: {chains} | всего фаз (цепочка × A–D): {n_phases} "
        f"| прогонов curl на фазу: {runs} | sleep между curl: {sleep_ms} мс",
        quiet,
    )
    if run_trace:
        log(f"Ideco SSH (trace): {ideco_host}", quiet)
    else:
        log("Trace на Ideco: выключен (run_ideco_trace=false)", quiet)

    cfg_snapshot = {
        "runs_per_phase": runs,
        "sleep_ms": sleep_ms,
        "curl_progress_every": progress_every,
        "chains_to_run": chains,
    }
    log(f"Ключевые параметры из конфига: {cfg_snapshot}", quiet)

    try:
        for chain in chains:
            chain_file = vp["chain_files"][chain]
            log(f"\n--- Цепочка файла на VPS: {chain} → {chain_file} ---", quiet)

            for letter, cert_comp, tc_delay in PHASES:
                compression = "zlib" if cert_comp else "off"
                delay_ms = 50 if tc_delay else 0

                log("", quiet)
                log(
                    f"ФАЗА chain={chain} mode={letter} | сжатие(zlib)={cert_comp} | tc 50ms={tc_delay} "
                    f"| метки CSV: compression={compression} delay_ms={delay_ms}",
                    quiet,
                )

                remote_bash = build_vps_script(vp, tc_iface, chain_file, cert_comp, tc_delay)
                rc = run_ssh_script(
                    vps_host,
                    ssh_extra,
                    remote_bash,
                    dry,
                    quiet=quiet,
                    dump_script=dump,
                    label=f"VPS старт сервера ({letter})",
                )
                if rc != 0 and not dry:
                    log(f"ОШИБКА: VPS вернул код {rc}. Прерывание.", quiet)
                    return rc

                trace_path = out_dir / f"{chain}_{letter}_ideco_trace.txt"
                if run_trace:
                    tcmd = ideco_trace_command(cfg)
                    _rc_trace, out = run_ssh_capture(
                        ideco_host,
                        ssh_extra,
                        tcmd,
                        dry,
                        quiet=quiet,
                        label=f"Ideco openssl trace ({letter})",
                    )
                    if not dry:
                        trace_path.write_text(out, encoding="utf-8")
                        log(f"Запись trace: {trace_path.resolve()} ({len(out)} байт)", quiet)

                csv_name = phase_csv_name(chain, letter, compression, delay_ms)
                csv_path = out_dir / csv_name
                err_path = out_dir / (Path(csv_name).stem + ".err.log")

                log(f"Локальные замеры curl → {csv_path.resolve()}", quiet)
                if not dry:
                    collect_series(
                        url=url,
                        runs=runs,
                        sleep_ms=sleep_ms,
                        output=csv_path,
                        chain=chain,
                        compression=compression,
                        delay_ms=delay_ms,
                        insecure_k=insecure_k,
                        stderr_log=err_path,
                        progress_every=progress_every if not quiet else 0,
                    )
                    log(f"Файл CSV готов: {csv_path} ({runs} строк)", quiet)
                    log(f"Stderr curl (если был): {err_path}", quiet)

                log(f"VPS: остановка сервера и снятие tc после фазы {letter}", quiet)
                vps_teardown_only(tc_iface, dry, vps_host, ssh_extra, quiet=quiet, dump_script=dump)

        log("\n=== Все этапы завершены успешно. ===", quiet)
        return 0

    except KeyboardInterrupt:
        log("\nПрервано пользователем — teardown VPS…", quiet)
        vps_teardown_only(
            cfg.get("tc_iface"),
            dry,
            cfg["vps_ssh"],
            list(cfg.get("ssh_extra_args", [])),
            quiet=quiet,
            dump_script=dump,
        )
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
