#!/usr/bin/env python3
"""
Анализ CSV из collect_tls_metrics.py или из handshake_from_pcap.py (tshark): сводная статистика и графики (matplotlib).

Графики: по одному PNG на каждую цепочку (small / medium / large); 4 столбца — режимы A–D,
разные цвета. Расшифровка режимов — в отдельном `modes_legend.txt` рядом с PNG (имя задаётся через --modes-legend).

Сводку можно не пересчитывать из runs: флаг `--from-summary` читает готовый `summary.csv` или `summary.json`,
строит только графики (и при необходимости modes_legend.txt).
"""

from __future__ import annotations

import argparse
import csv
import glob
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib as mpl  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

TEXT_INK = "#000000"
GRID_COLOR = "#D9D9D9"

# Подпись цепочки в заголовке графика (без VPS и технических имён файлов)
CHAIN_TITLE_RU: dict[str, str] = {
    "small": "малой цепочки сертификатов",
    "medium": "средней цепочки сертификатов",
    "large": "большой цепочки сертификатов",
}

# Цвета столбцов A–D (режимы различимы на печати и на экране)
MODE_SPECS: list[dict[str, str | int]] = [
    {
        "letter": "A",
        "compression": "off",
        "delay_ms": 0,
        "color": "#4a6db9",
        "description": (
            "Без сжатия цепочки в сертификате (openssl s_server: без -cert_comp).\n"
            "Дополнительная задержка канала не задаётся (tc netem выключен)."
        ),
    },
    {
        "letter": "B",
        "compression": "zlib",
        "delay_ms": 0,
        "color": "#6bcf7a",
        "description": (
            "Сжатие цепочки zlib по RFC 8879 (openssl: включено сжатие сертификата).\n"
            "Дополнительная задержка канала не задаётся (tc netem выключен)."
        ),
    },
    {
        "letter": "C",
        "compression": "off",
        "delay_ms": 100,
        "color": "#e6c86e",
        "description": (
            "Без сжатия цепочки (без -cert_comp).\n"
            "На стороне сервера эмулируется односторонняя задержка 100 ms (tc qdisc netem)."
        ),
    },
    {
        "letter": "D",
        "compression": "zlib",
        "delay_ms": 100,
        "color": "#ff8b7a",
        "description": (
            "Сжатие zlib RFC 8879 (сжатие сертификата включено).\n"
            "На стороне сервера эмулируется односторонняя задержка 100 ms (tc qdisc netem)."
        ),
    },
]


def apply_matplotlib_style() -> None:
    mpl.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
            "font.size": 10,
            "text.color": TEXT_INK,
            "axes.titlesize": 14,
            "axes.labelsize": 10,
            "axes.titlecolor": TEXT_INK,
            "axes.labelcolor": TEXT_INK,
            "xtick.color": TEXT_INK,
            "ytick.color": TEXT_INK,
            "xtick.labelsize": 9,
            "ytick.labelsize": 10,
        }
    )


def p95(series: pd.Series) -> float:
    return float(series.quantile(0.95))


def ensure_tls_ms(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    if "tls_handshake_ms" in out.columns:
        out["tls_handshake_ms"] = pd.to_numeric(out["tls_handshake_ms"], errors="coerce")
    if "delay_ms" in out.columns:
        out["delay_ms"] = pd.to_numeric(out["delay_ms"], errors="coerce").astype("Int64")
    if "tls_handshake_ms" not in out.columns or out["tls_handshake_ms"].isna().all():
        if "tls_handshake_s" in out.columns:
            out["tls_handshake_ms"] = out["tls_handshake_s"].astype(float) * 1000.0
        else:
            raise ValueError("Нужны столбцы tls_handshake_ms или tls_handshake_s")
    return out


def summary_table(df: pd.DataFrame) -> pd.DataFrame:
    df = ensure_tls_ms(df)
    group_cols = [c for c in ("chain", "compression", "delay_ms") if c in df.columns]
    if not group_cols:
        s = df["tls_handshake_ms"].dropna()
        return pd.DataFrame(
            [
                {
                    "count": len(s),
                    "mean": float(s.mean()),
                    "median": float(s.median()),
                    "std": float(s.std(ddof=1)) if len(s) > 1 else 0.0,
                    "p95": p95(s),
                }
            ]
        )
    agg = (
        df.groupby(group_cols, dropna=False)["tls_handshake_ms"]
        .agg(count="count", mean="mean", median="median", std="std", p95=lambda x: p95(x))
        .reset_index()
    )
    return agg


def load_summary_table(path: Path) -> pd.DataFrame:
    """Загрузка готовой сводки (как после summary_table): нужны chain, compression, delay_ms, mean."""
    path = path.expanduser()
    if not path.is_file():
        raise FileNotFoundError(path)
    suf = path.suffix.lower()
    if suf == ".json":
        summ = pd.read_json(path, orient="records")
    elif suf == ".csv":
        summ = pd.read_csv(path)
    else:
        raise ValueError(f"Неподдерживаемый формат сводки: {path} (ожидаются .csv или .json)")
    required = ("chain", "compression", "delay_ms", "mean")
    missing = [c for c in required if c not in summ.columns]
    if missing:
        raise ValueError(f"В сводке нет колонок: {missing}; есть: {list(summ.columns)}")
    summ = summ.copy()
    summ["mean"] = pd.to_numeric(summ["mean"], errors="coerce")
    return summ


def _mean_from_summary(
    summ: pd.DataFrame,
    chain: str,
    compression: str,
    delay_ms: int,
) -> float | None:
    s = summ.copy()
    s["chain"] = s["chain"].astype(str).str.strip()
    s["compression"] = s["compression"].astype(str).str.strip()
    s["delay_ms"] = pd.to_numeric(s["delay_ms"], errors="coerce").astype("Int64")
    row = s[
        (s["chain"] == chain)
        & (s["compression"] == compression)
        & (s["delay_ms"] == delay_ms)
    ]
    if row.empty:
        return None
    return float(row["mean"].iloc[0])


def write_modes_legend_txt(out_dir: Path, filename: str) -> Path:
    """Текстовая расшифровка режимов A–D для подписи к графикам."""
    lines: list[str] = [
        "Режимы эксперимента (столбцы A–D на графиках tls_handshake_chain_*.png)",
        "",
        "Метрика на графиках — среднее время TLS-рукопожатия по серии замеров (мс).",
        "Цвет столбца соответствует режиму:",
        "",
    ]
    for spec in MODE_SPECS:
        letter = str(spec["letter"])
        color = str(spec["color"])
        desc = str(spec["description"]).strip().replace("\n", "\n   ")
        lines.append(f"{letter} ({color})")
        lines.append(f"   {desc}")
        lines.append("")
    lines.append("Цепочки сертификатов на графиках: small — малая, medium — средняя, large — большая.")
    path = out_dir / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return path


def plot_tls_bar_charts(summ: pd.DataFrame, out_dir: Path) -> list[Path]:
    """Три отдельных PNG (small / medium / large): по 4 столбца A–D, цвета из MODE_SPECS; среднее tls_handshake_ms; без легенды."""
    apply_matplotlib_style()
    out_dir.mkdir(parents=True, exist_ok=True)

    chains_order = ["small", "medium", "large"]
    saved: list[Path] = []

    for chain in chains_order:
        heights: list[float] = []
        for spec in MODE_SPECS:
            v = _mean_from_summary(summ, str(chain), str(spec["compression"]), int(spec["delay_ms"]))
            heights.append(v if v is not None else 0.0)

        colors = [str(s["color"]) for s in MODE_SPECS]
        fig, ax = plt.subplots(figsize=(8.0, 5.0))
        fig.patch.set_facecolor("white")

        chain_ru = CHAIN_TITLE_RU.get(chain, chain)
        x = list(range(len(MODE_SPECS)))
        bars = ax.bar(
            x,
            heights,
            color=colors,
            edgecolor="#333333",
            linewidth=0.45,
            width=0.72,
        )
        ax.set_xticks(x)
        ax.set_xticklabels([str(s["letter"]) for s in MODE_SPECS])
        ax.set_xlabel("Режим эксперимента", color=TEXT_INK)
        ax.set_ylabel("Среднее время TLS-рукопожатия, мс", color=TEXT_INK)
        ax.set_title(
            f"Среднее время TLS-рукопожатия для {chain_ru}",
            fontsize=14,
            color=TEXT_INK,
            pad=12,
        )
        ax.grid(axis="y", color=GRID_COLOR, linestyle="-", linewidth=0.8, alpha=0.95)
        ax.set_axisbelow(True)
        ymax = max(heights) if heights else 1.0
        ax.set_ylim(0, ymax * 1.22 if ymax > 0 else 1.0)

        for rect, h in zip(bars, heights):
            if h > 0:
                ax.text(
                    rect.get_x() + rect.get_width() / 2.0,
                    h + ymax * 0.012,
                    f"{h:.0f}",
                    ha="center",
                    va="bottom",
                    fontsize=9,
                    color=TEXT_INK,
                )

        fig.subplots_adjust(left=0.10, right=0.96, top=0.88, bottom=0.11)

        out_png = out_dir / f"tls_handshake_chain_{chain}.png"
        fig.savefig(out_png, dpi=150, facecolor="white", bbox_inches="tight")
        plt.close(fig)
        saved.append(out_png)

    return saved


def main() -> int:
    ap = argparse.ArgumentParser(description="Сводка и графики по CSV замеров TLS")
    ap.add_argument(
        "inputs",
        nargs="*",
        default=[],
        help="Файлы CSV или шаблоны (например runs/*.csv); не нужны при --from-summary",
    )
    ap.add_argument(
        "--from-summary",
        type=Path,
        default=None,
        help="Построить графики только из готовой сводки (.csv или .json); runs не читаются",
    )
    ap.add_argument(
        "--summary",
        default="summary.csv",
        help="Имя файла сводки при чтении из runs (в output-dir); также пишется summary.json с тем же префиксом",
    )
    ap.add_argument(
        "--no-summary-json",
        action="store_true",
        help="При агрегации из runs не записывать JSON рядом с CSV",
    )
    ap.add_argument(
        "--output-dir",
        default=None,
        help="Каталог для PNG и сводок; по умолчанию figures или каталог файла --from-summary",
    )
    ap.add_argument(
        "--modes-legend",
        default="modes_legend.txt",
        help="Имя файла с расшифровкой режимов A–D (в output-dir); пустая строка — не создавать",
    )
    args = ap.parse_args()

    if args.from_summary:
        summ_path = args.from_summary.expanduser().resolve()
        summ = load_summary_table(summ_path)
        out_dir = Path(args.output_dir) if args.output_dir is not None else summ_path.parent
        out_dir = out_dir.expanduser().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        print(f"Loaded summary from {summ_path}")
    else:
        if not args.inputs:
            ap.error("укажите CSV замеров или --from-summary ПУТЬ")
        out_dir = Path(args.output_dir) if args.output_dir is not None else Path("figures")
        out_dir = out_dir.expanduser().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        paths: list[Path] = []
        for pat in args.inputs:
            expanded = sorted(glob.glob(pat))
            if expanded:
                paths.extend(Path(p) for p in expanded)
            elif Path(pat).exists():
                paths.append(Path(pat))
            else:
                raise FileNotFoundError(pat)

        frames = [pd.read_csv(p) for p in paths]
        df = pd.concat(frames, ignore_index=True)
        summ = summary_table(df)
        summary_path = out_dir / args.summary
        summ.to_csv(summary_path, index=False, quoting=csv.QUOTE_NONNUMERIC)
        print(f"Written {summary_path}")
        if not args.no_summary_json:
            json_path = summary_path.with_suffix(".json")
            summ.to_json(json_path, orient="records", force_ascii=False, indent=2)
            print(f"Written {json_path}")

    chart_paths = plot_tls_bar_charts(summ, out_dir)
    for p in chart_paths:
        print(f"Saved {p}")

    ml = str(args.modes_legend).strip()
    if ml:
        legend_path = write_modes_legend_txt(out_dir, ml)
        print(f"Written {legend_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
