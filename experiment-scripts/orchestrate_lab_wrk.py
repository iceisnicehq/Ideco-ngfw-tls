#!/usr/bin/env python3
"""
Оркестрация лаборатории: нагрузка (hey или wrk) + tcpdump на клиентах,
openssl s_server + tc на ideco.local, mpstat на NGFW.

Конфиг: lab_wrk_config.json (пароли задаются в JSON или через auth_env при его наличии).

При любой ошибке SSH/SCP/hey/tshark скрипт завершается с ненулевым кодом.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def ts() -> str:
    return time.strftime("%H:%M:%S")


def log(msg: str) -> None:
    print(f"[{ts()}] {msg}", file=sys.stderr, flush=True)


def env_password(auth_env: str) -> str:
    v = (os.environ.get(auth_env) or "").strip()
    if not v:
        raise RuntimeError(f"Переменная окружения {auth_env!r} не задана (пароль для SSH)")
    return v


def ssh_password(entity: dict[str, Any]) -> str:
    if entity.get("ssh_password") is not None:
        return str(entity["ssh_password"])
    if entity.get("password") is not None:
        return str(entity["password"])
    ae = entity.get("auth_env")
    if ae:
        return env_password(str(ae))
    raise RuntimeError(
        f"Задайте ssh_password (или password / auth_env) для хоста {entity.get('ssh_host')!r}"
    )


def ssh_base(extra: list[str], user: str, host: str) -> list[str]:
    return ["ssh", *extra, f"{user}@{host}"]


def scp_to(
    password: str,
    extra: list[str],
    user: str,
    host: str,
    local: Path,
    remote: str,
) -> None:
    env = os.environ.copy()
    env["SSHPASS"] = password
    cmd = ["sshpass", "-e", "scp", *extra, str(local), f"{user}@{host}:{remote}"]
    subprocess.run(cmd, env=env, check=True)


def scp_from(
    password: str,
    extra: list[str],
    user: str,
    host: str,
    remote: str,
    local: Path,
) -> None:
    local.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["SSHPASS"] = password
    cmd = ["sshpass", "-e", "scp", *extra, f"{user}@{host}:{remote}", str(local)]
    subprocess.run(cmd, env=env, check=True)


def run_remote_script(
    *,
    user: str,
    host: str,
    password: str,
    ssh_extra: list[str],
    script: str,
    label: str,
) -> None:
    env = os.environ.copy()
    env["SSHPASS"] = password
    cmd = ["sshpass", "-e", *ssh_base(ssh_extra, user, host), "bash", "-s"]
    log(f"{label}: ssh {user}@{host} bash -s ({len(script)} bytes)")
    r = subprocess.run(cmd, input=script.encode(), env=env, check=True)


def install_trusted_leaf_on_clients(cfg: dict[str, Any], ssh_ex: list[str]) -> None:
    if not cfg.get("distribute_trusted_leaf", False):
        return
    srv = cfg["server"]
    spw = ssh_password(srv)
    cert_dir = str(srv["cert_dir"]).rstrip("/")
    leaf_name = str(srv["leaf_cert"])
    remote_leaf = f"{cert_dir}/{leaf_name}"

    env_srv = os.environ.copy()
    env_srv["SSHPASS"] = spw
    cat_cmd = [
        "sshpass",
        "-e",
        *ssh_base(ssh_ex, str(srv["ssh_user"]), str(srv["ssh_host"])),
        "cat",
        remote_leaf,
    ]
    log("[trust] fetch leaf.crt с сервера")
    r = subprocess.run(cat_cmd, env=env_srv, capture_output=True, check=True)
    pem_bytes = r.stdout
    if not pem_bytes.strip():
        raise RuntimeError("[trust] пустой leaf с сервера — проверьте пути и сертификат")

    for c in cfg["clients"]:
        cpw = ssh_password(c)
        env_c = os.environ.copy()
        env_c["SSHPASS"] = cpw
        b64 = base64.b64encode(pem_bytes).decode("ascii")
        install_script = f"""set -euo pipefail
umask 022
echo {shlex.quote(b64)} | base64 -d > /usr/local/share/ca-certificates/ideco-local.crt
if command -v update-ca-certificates >/dev/null 2>&1; then
  update-ca-certificates
elif command -v update-ca-trust >/dev/null 2>&1; then
  update-ca-trust extract >/dev/null 2>&1 || update-ca-trust
else
  echo 'Нет update-ca-certificates / update-ca-trust' >&2
  exit 1
fi
"""
        cmd = ["sshpass", "-e", *ssh_base(ssh_ex, str(c["ssh_user"]), str(c["ssh_host"])), "bash", "-s"]
        label = f"[trust] install CA on {c['id']}"
        log(label)
        subprocess.run(cmd, input=install_script.encode(), env=env_c, check=True)


def phase_id(chain: str, compression: str, delay_ms: int) -> str:
    return f"{chain}_{compression}_delay{delay_ms}"


def build_server_script(cfg: dict[str, Any], chain: str, compression: str, delay_ms: int) -> str:
    s = cfg["server"]
    iface = s["iface"]
    cert_dir = s["cert_dir"].rstrip("/")
    leaf = f"{cert_dir}/{s['leaf_cert']}"
    key = f"{cert_dir}/{s['leaf_key']}"
    chain_pem = cfg["chain_remote_paths"][chain]
    obin = s["openssl_bin"]
    zlib = compression == "zlib"

    parts: list[str] = [
        obin,
        "s_server",
        "-accept",
        "443",
        "-www",
        "-tls1_3",
        "-cert",
        leaf,
        "-key",
        key,
        "-cert_chain",
        chain_pem,
    ]
    for x in s.get("s_server_extra_args") or []:
        parts.append(x)
    if zlib:
        parts.extend(shlex.split(s.get("cert_comp_zlib_flag", "-cert_comp zlib")))

    server_cmd = "nohup " + " ".join(shlex.quote(p) for p in parts) + " > /tmp/s_server_lab.log 2>&1 &"

    if delay_ms > 0:
        tc = f"""
tc qdisc del dev {shlex.quote(iface)} root 2>/dev/null || true
tc qdisc add dev {shlex.quote(iface)} root netem delay {int(delay_ms)}ms
"""
    else:
        tc = f"tc qdisc del dev {shlex.quote(iface)} root 2>/dev/null || true\n"

    ld = (s.get("ld_library_path") or "").strip()
    ldline = f"export LD_LIBRARY_PATH={shlex.quote(ld)}\n" if ld else ""

    return f"""set -euo pipefail
pkill -f '[o]penssl s_server' || true
sleep 1
{tc}{ldline}{server_cmd}
sleep 2
"""


def run_phase(
    cfg: dict[str, Any],
    script_dir: Path,
    chain: str,
    compression: str,
    delay_ms: int,
    *,
    dry_run: bool,
) -> None:
    ssh_ex = list(cfg.get("ssh_extra_args") or [])
    pid = phase_id(chain, compression, delay_ms)
    target_url = str(
        cfg.get("target_url")
        or (cfg.get("wrk_fallback") or {}).get("url")
        or "https://ideco.local/"
    )
    load = cfg.get("load") or {}
    tool = str(load.get("tool") or "hey").lower()
    sync_sleep = float(cfg.get("sync_sleep_sec") or 2)
    grace = float(cfg.get("post_load_grace_sec") or 3)

    wrk_fb = cfg.get("wrk_fallback") or cfg.get("wrk") or {}

    rdir = Path(cfg.get("results_dir") or "../results/lab_wrk").resolve()
    phase_dir = rdir / pid
    phase_dir.mkdir(parents=True, exist_ok=True)

    log(f"=== Фаза {pid} ===")

    srv = cfg["server"]
    srv_script = build_server_script(cfg, chain, compression, delay_ms)
    if dry_run:
        print(srv_script)
        return

    run_remote_script(
        user=str(srv["ssh_user"]),
        host=str(srv["ssh_host"]),
        password=ssh_password(srv),
        ssh_extra=ssh_ex,
        script=srv_script,
        label="server",
    )

    ng = cfg.get("ngfw") or {}
    if ng.get("ssh_host"):
        remote_mp = f"{ng.get('remote_log_dir', '/tmp/lab_mpstat').rstrip('/')}/{pid}.log"
        mpstat_sec = int(ng.get("mpstat_seconds") or 180)
        mp_cmd = (ng.get("mpstat_cmd") or "").strip() or f"mpstat 1 {mpstat_sec}"
        mp_script = f"""set -euo pipefail
mkdir -p {shlex.quote(str(Path(remote_mp).parent))}
nohup bash -lc {shlex.quote(mp_cmd)} > {shlex.quote(remote_mp)} 2>&1 &
echo started mpstat -> {remote_mp}
"""
        run_remote_script(
            user=str(ng["ssh_user"]),
            host=str(ng["ssh_host"]),
            password=ssh_password(ng),
            ssh_extra=ssh_ex,
            script=mp_script,
            label="ngfw mpstat",
        )

    remote_base = cfg.get("remote_pcap_dir") or "/tmp/lab_wrk_pcap"

    lua_local = script_dir / str(wrk_fb.get("lua_script") or "wrk_close.lua")
    remote_lua = "/tmp/lab_wrk_close.lua"

    clients_data: list[dict[str, Any]] = []
    for c in cfg["clients"]:
        cid = str(c["id"])
        host = str(c["ssh_host"])
        user = str(c["ssh_user"])
        pw = ssh_password(c)
        cip = str(c["client_ip"])
        iface = str(c.get("iface") or "enp0s3")
        pcap_rel = f"{remote_base}/{pid}_{cid}.pcap"

        if tool == "wrk":
            if not lua_local.is_file():
                raise FileNotFoundError(f"Lua для wrk не найдена: {lua_local}")
            scp_to(pw, ssh_ex, user, host, lua_local, remote_lua)

        dump_start = f"""set -euo pipefail
mkdir -p {shlex.quote(remote_base)}
rm -f {shlex.quote(pcap_rel)}
nohup tcpdump -i {shlex.quote(iface)} -U -w {shlex.quote(pcap_rel)} port 443 > /tmp/tcpdump_{cid}.log 2>&1 &
echo $! > /tmp/tcpdump_{cid}.pid
"""
        clients_data.append(
            {
                "id": cid,
                "host": host,
                "user": user,
                "pw": pw,
                "cip": cip,
                "dump_start": dump_start,
                "pcap_rel": pcap_rel,
            }
        )

    for cd in clients_data:
        run_remote_script(
            user=cd["user"],
            host=cd["host"],
            password=cd["pw"],
            ssh_extra=ssh_ex,
            script=cd["dump_start"],
            label=f"tcpdump start {cd['id']}",
        )

    log(f"Ожидание {sync_sleep}s перед нагрузкой")
    time.sleep(sync_sleep)

    if tool == "hey":
        req = int(load.get("requests_per_client", 100))
        conc = int(load.get("concurrency", 10))
        hey_bin = str(load.get("hey_bin") or "hey")
        ex_args = load.get("extra_args") or ["-disable-keepalive"]
        ex_s = " ".join(shlex.quote(a) for a in ex_args)
        hey_line = f"{shlex.quote(hey_bin)} -n {req} -c {conc} {ex_s} {shlex.quote(target_url)}"

        procs: list[subprocess.Popen[bytes]] = []
        for cd in clients_data:
            env = os.environ.copy()
            env["SSHPASS"] = cd["pw"]
            remote = f"set -euo pipefail; {hey_line}"
            cmd = [
                "sshpass",
                "-e",
                *ssh_base(ssh_ex, cd["user"], cd["host"]),
                "bash",
                "-lc",
                remote,
            ]
            log(f"hey start {cd['id']}: {hey_line}")
            procs.append(subprocess.Popen(cmd, env=env))

        rc_ls = [p.wait() for p in procs]
        if any(rc != 0 for rc in rc_ls):
            raise RuntimeError(f"hey на одном из клиентов завершился с кодом: {rc_ls}")

    elif tool == "wrk":
        dur = int(wrk_fb.get("duration_sec") or 60)
        wrk_t = int(wrk_fb.get("threads") or 4)
        wrk_c = int(wrk_fb.get("connections") or 50)
        procs = []
        for cd in clients_data:
            env = os.environ.copy()
            env["SSHPASS"] = cd["pw"]
            remote = (
                f"set -euo pipefail; wrk -t{wrk_t} -c{wrk_c} -d{dur}s "
                f"-s {shlex.quote(remote_lua)} {shlex.quote(target_url)}"
            )
            cmd = [
                "sshpass",
                "-e",
                *ssh_base(ssh_ex, cd["user"], cd["host"]),
                "bash",
                "-lc",
                remote,
            ]
            log(f"wrk start {cd['id']}")
            procs.append(subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        rc_ls = [p.wait() for p in procs]
        if any(rc != 0 for rc in rc_ls):
            raise RuntimeError(f"wrk на одном из клиентов завершился с кодом: {rc_ls}")
    else:
        raise RuntimeError(f"Неизвестный load.tool: {tool} (ожидаются hey или wrk)")

    log(f"Пауза {grace}s после нагрузки")
    time.sleep(grace)

    cleanup_tpl = """set -euo pipefail
if [ -f /tmp/tcpdump_{cid}.pid ]; then kill -INT $(cat /tmp/tcpdump_{cid}.pid) 2>/dev/null || true; fi
sleep 1
"""
    for cd in clients_data:
        run_remote_script(
            user=cd["user"],
            host=cd["host"],
            password=cd["pw"],
            ssh_extra=ssh_ex,
            script=cleanup_tpl.replace("{cid}", cd["id"]),
            label=f"tcpdump stop {cd['id']}",
        )

    for cd in clients_data:
        local_p = phase_dir / f"{cd['id']}.pcap"
        scp_from(cd["pw"], ssh_ex, cd["user"], cd["host"], cd["pcap_rel"], local_p)
        if not local_p.is_file() or local_p.stat().st_size < 24:
            raise RuntimeError(f"Некорректный или пустой pcap: {local_p}")

    if ng.get("ssh_host"):
        remote_mp = f"{ng.get('remote_log_dir', '/tmp/lab_mpstat').rstrip('/')}/{pid}.log"
        scp_from(
            ssh_password(ng),
            ssh_ex,
            str(ng["ssh_user"]),
            str(ng["ssh_host"]),
            remote_mp,
            phase_dir / "mpstat.log",
        )

    hf = script_dir / "handshake_from_pcap.py"
    for cd in clients_data:
        lp = phase_dir / f"{cd['id']}.pcap"
        out_csv = phase_dir / f"handshakes_{cd['id']}.csv"
        cmd = [
            sys.executable,
            str(hf),
            str(lp),
            "--client-ip",
            cd["cip"],
            "--chain",
            chain,
            "--compression",
            compression,
            "--delay-ms",
            str(delay_ms),
            "--source-client",
            cd["id"],
            "--phase-id",
            pid,
            "--wrk-url",
            target_url,
            "-o",
            str(out_csv),
        ]
        subprocess.run(cmd, check=True)
        if not out_csv.is_file():
            raise RuntimeError(f"Не создан {out_csv}")
        with open(out_csv, newline="", encoding="utf-8") as f:
            n = sum(1 for _ in f) - 1
        if n < 1:
            raise RuntimeError(
                f"В {out_csv} нет измеренных рукопожатий (tshark). Проверьте pcap и SNI/HTTPS."
            )


def merge_all_handshakes(results_dir: Path) -> Path:
    all_rows: list[dict[str, str]] = []
    headers: list[str] | None = None
    for csv_path in sorted(results_dir.rglob("handshakes_*.csv")):
        with open(csv_path, newline="", encoding="utf-8") as f:
            r = csv.DictReader(f)
            if headers is None:
                headers = r.fieldnames or []
            for row in r:
                all_rows.append(dict(row))
    merged = results_dir / "handshakes_all.csv"
    if not headers:
        log("Нет handshake CSV для объединения")
        return merged
    with open(merged, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        w.writeheader()
        for row in all_rows:
            w.writerow(row)
    log(f"Merged {len(all_rows)} rows -> {merged}")
    return merged


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    default_cfg = script_dir / "lab_wrk_config.json"

    ap = argparse.ArgumentParser(description="Оркестрация hey/wrk + tcpdump + s_server + mpstat")
    ap.add_argument(
        "-c",
        "--config",
        type=Path,
        default=default_cfg,
        help=f"JSON конфиг (по умолчанию {default_cfg.name} рядом со скриптом)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Только напечатать скрипт настройки сервера для первой фазы",
    )
    ap.add_argument(
        "--merge-only",
        action="store_true",
        help="Только объединить handshakes_*.csv в results_dir из конфига",
    )
    args = ap.parse_args()
    cfg_path = args.config.expanduser().resolve()
    if not cfg_path.is_file():
        print(f"Нет файла конфигурации: {cfg_path}", file=sys.stderr)
        return 1
    with open(cfg_path, encoding="utf-8") as f:
        cfg = json.load(f)

    rdir = Path(cfg.get("results_dir") or "../results/lab_wrk").resolve()
    if args.merge_only:
        merge_all_handshakes(rdir)
        return 0

    ph = cfg.get("phases") or {}
    chains: list[str] = list(ph.get("chains") or ["small", "medium", "large"])
    comps: list[str] = list(ph.get("compressions") or ["off", "zlib"])
    delays: list[int] = [int(x) for x in (ph.get("delay_ms") or [0, 100])]

    ssh_ex = list(cfg.get("ssh_extra_args") or [])

    if args.dry_run:
        print(build_server_script(cfg, chains[0], comps[0], delays[0]))
        return 0

    install_trusted_leaf_on_clients(cfg, ssh_ex)

    for chain in chains:
        for compression in comps:
            for delay_ms in delays:
                run_phase(cfg, script_dir, chain, compression, delay_ms, dry_run=False)

    merge_all_handshakes(rdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
