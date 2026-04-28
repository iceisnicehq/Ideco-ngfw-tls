# Скрипты эксперимента TLS / RFC 8879

Эксперимент на стенде — **только zlib**: значение метки `--compression` — **`off`** или **`zlib`** (метка `zlib` соответствует серверу с включённым **`-cert_comp`** на VPS; см. [eksperiment-rfc8879-vps-ideco-guide.md](../eksperiment-rfc8879-vps-ideco-guide.md)).

## Зависимости

Python 3.10+ и установленный **`curl`** в `PATH` (на Ideco NGFW или клиенте Linux).

```bash
cd experiment-scripts
python3 -m venv .venv
# Windows PowerShell:
# .venv\Scripts\Activate.ps1
# Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

## Сбор замеров (`collect_tls_metrics.py`)

Запускать на машине, где выполняются HTTPS-запросы к тестовому серверу (обычно консоль Ideco NGFW или ALT).

Пример — 250 запросов (дефолт), метки сценария для последующей группировки:

```bash
python3 collect_tls_metrics.py \
  --url "https://ideco.theworkpc.com/" \
  --runs 250 \
  --sleep-ms 150 \
  --chain large \
  --compression off \
  --delay-ms 0 \
  --insecure-k \
  --output ../runs/large_off_delay0.csv \
  --stderr-log ../runs/large_off_delay0.err.log
```

Параметры:

| Параметр | Описание |
|----------|----------|
| `--url` | Полный HTTPS URL |
| `--runs` | Число повторов (по умолчанию **250**) |
| `--sleep-ms` | Пауза между запросами (по умолчанию 150 мс) |
| `--chain` | Метка уровня цепочки: `small` / `medium` / `large` |
| `--compression` | Метка: `off` или `zlib` |
| `--delay-ms` | Метка задержки на стороне сервера: `0` или `50` (сама задержка включается на VPS через `tc`) |
| `--insecure-k` | Передаёт в curl `-k` (самоподписанные сертификаты) |
| `--output` | Путь к CSV |
| `--stderr-log` | Опционально: сохранить stderr curl |

Столбцы CSV: `run_index`, `timestamp_iso`, `url`, `chain`, `compression`, `delay_ms`, времена curl, `tls_handshake_s`, `tls_handshake_ms`, `curl_exit_code`.

Метрика: **`tls_handshake_ms`** ≈ время TLS после установления TCP (`time_appconnect − time_connect`).

## Интерактивный проход A–D (`collect_tls_abcd.py`)

Один запуск — одна цепочка (`small` / `medium` / `large`): подряд записываются четыре CSV (режимы A→B→C→D). Между режимами скрипт ждёт **Enter**, чтобы вы успели переключить `s_server` и `tc` на VPS.

По умолчанию: **100** запросов на режим, пауза **100** мс между запросами.

Запускать из каталога `experiment-scripts` (чтобы находился модуль `collect_tls_metrics`):

```bash
cd experiment-scripts
python3 collect_tls_abcd.py \
  --url "https://ideco.theworkpc.com/" \
  --chain small \
  --insecure-k \
  --output-dir ../runs
```

Файлы: `{chain}_A_off_delay0.csv`, `{chain}_B_zlib_delay0.csv`, `{chain}_C_off_delay50.csv`, `{chain}_D_zlib_delay50.csv` и рядом `.err.log`.

Флаг **`--yes`** — без пауз Enter (только для отладки; конфигурация VPS должна подходить ко всем режимам сама по себе).

## Анализ и графики (`analyze_tls_results.py`)

Объединяет один или несколько CSV и строит сводную таблицу + boxplot.

```bash
python3 analyze_tls_results.py ../runs/*.csv --output-dir ../figures --summary summary.csv
```

Результат:

- `figures/summary.csv` — по группам `chain`, `compression`, `delay_ms`: count, mean, median, std, p95  
- `figures/boxplot_by_scenario.png` — все комбинации меток  
- `figures/boxplot_by_delay.png` — если есть несколько значений `delay_ms`

## Полная матрица (12 файлов × 250 строк)

Для каждой комбинации (3 цепочки × 2 режима сжатия × 2 задержки) выполните отдельный прогон с корректными `--chain`, `--compression`, `--delay-ms`, затем объедините все CSV одним вызовом `analyze_tls_results.py`.

Подробности топологии VPS + Ideco — в [eksperiment-rfc8879-vps-ideco-guide.md](../eksperiment-rfc8879-vps-ideco-guide.md).
