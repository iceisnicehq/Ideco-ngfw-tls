#!/usr/bin/env python3
"""
Анализ CSV из collect_tls_metrics.py: сводная статистика и графики (matplotlib).
"""

from __future__ import annotations

import argparse
import csv
import glob
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402


def p95(series: pd.Series) -> float:
    return float(series.quantile(0.95))


def ensure_tls_ms(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    if "tls_handshake_ms" not in out.columns or out["tls_handshake_ms"].isna().all():
        if "tls_handshake_s" in out.columns:
            out["tls_handshake_ms"] = out["tls_handshake_s"].astype(float) * 1000.0
        else:
            raise ValueError("Нужны столбцы tls_handshake_ms или tls_handshake_s")
    return out


def scenario_label(row: pd.Series, cols: list[str]) -> str:
    return "|".join(str(row.get(c, "")) for c in cols)


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


def plot_boxplots(df: pd.DataFrame, out_dir: Path) -> None:
    df = ensure_tls_ms(df)
    out_dir.mkdir(parents=True, exist_ok=True)

    label_cols = [c for c in ("chain", "compression", "delay_ms") if c in df.columns]
    if label_cols:
        df["_scenario"] = df.apply(lambda r: scenario_label(r, label_cols), axis=1)
    else:
        df["_scenario"] = "all"

    scenarios = sorted(df["_scenario"].unique())
    data = [df.loc[df["_scenario"] == s, "tls_handshake_ms"].dropna().values for s in scenarios]

    fig, ax = plt.subplots(figsize=(max(10, len(scenarios) * 0.55), 6))
    ax.boxplot(data, labels=scenarios, showmeans=True)
    ax.set_ylabel("TLS handshake time (ms)")
    ax.set_title("TLS handshake duration by scenario")
    plt.xticks(rotation=35, ha="right")
    plt.tight_layout()
    fig.savefig(out_dir / "boxplot_by_scenario.png", dpi=150)
    plt.close(fig)

    delay_col = "delay_ms"
    if delay_col in df.columns and df[delay_col].nunique() > 1:
        delays = sorted(df[delay_col].unique())
        fig2, axes = plt.subplots(1, len(delays), figsize=(7 * len(delays), 6), squeeze=False)
        for idx, d in enumerate(delays):
            sub = df[df[delay_col] == d]
            scenarios_d = sorted(sub["_scenario"].unique())
            dat = [sub.loc[sub["_scenario"] == s, "tls_handshake_ms"].dropna().values for s in scenarios_d]
            ax2 = axes[0][idx]
            ax2.boxplot(dat, labels=scenarios_d, showmeans=True)
            ax2.set_ylabel("TLS handshake time (ms)")
            ax2.set_title(f"delay_ms={d}")
            plt.setp(ax2.xaxis.get_majorticklabels(), rotation=35, ha="right")
        plt.tight_layout()
        fig2.savefig(out_dir / "boxplot_by_delay.png", dpi=150)
        plt.close(fig2)


def main() -> int:
    ap = argparse.ArgumentParser(description="Сводка и графики по CSV замеров TLS")
    ap.add_argument(
        "inputs",
        nargs="+",
        help="Файлы CSV или шаблоны (например runs/*.csv)",
    )
    ap.add_argument(
        "--summary",
        default="summary.csv",
        help="Имя файла сводки (в output-dir)",
    )
    ap.add_argument(
        "--output-dir",
        default="figures",
        help="Каталог для PNG и summary.csv",
    )
    args = ap.parse_args()

    paths: list[Path] = []
    for pat in args.inputs:
        expanded = sorted(glob.glob(pat))
        if expanded:
            paths.extend(Path(p) for p in expanded)
        elif Path(pat).exists():
            paths.append(Path(pat))
        else:
            raise FileNotFoundError(pat)

    frames = []
    for p in paths:
        frames.append(pd.read_csv(p))

    df = pd.concat(frames, ignore_index=True)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summ = summary_table(df)
    summary_path = out_dir / args.summary
    summ.to_csv(summary_path, index=False, quoting=csv.QUOTE_NONNUMERIC)
    print(f"Written {summary_path}")

    plot_boxplots(df, out_dir)
    print(f"Plots saved under {out_dir}/")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
