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

## Полная автоматизация по SSH (`orchestrate_remote.py`)

Пошагово для ALT: **[ALT-LINUX-RUN.md](ALT-LINUX-RUN.md)** — какие файлы скопировать и как запустить.

Рядом со скриптом лежит **`remote_config.json`** (ваши хосты и пути); при необходимости отредактируйте только его.

Поведение скрипта:

1. SSH на **VPS** — старый `s_server`, `tc`, новый `openssl s_server` под фазу **A/B/C/D**.
2. Опционально SSH на **Ideco** — один `openssl s_client -trace` → `{chain}_{letter}_ideco_trace.txt`.
3. Локально — серия **curl** (`collect_series`), прогресс в консоль каждые **`curl_progress_every`** запросов из конфига.
4. SSH на **VPS** — teardown.

Флаги: **`--dry-run`**, **`--quiet`** (минимум текста), **`--dump-remote-scripts`** (печатать полный bash для VPS).

```bash
python3 orchestrate_remote.py -c remote_config.json
python3 orchestrate_remote.py --dry-run
```

Если на Ideco по SSH нет нормального `openssl`, задайте **`"run_ideco_trace": false`** в JSON.

## Анализ и графики (`analyze_tls_results.py`)

Объединяет один или несколько CSV и строит сводную таблицу + столбчатые диаграммы (среднее по режимам A–D для каждой цепочки).

```bash
python3 analyze_tls_results.py ../runs/*.csv --output-dir ../figures --summary summary.csv
```

Рядом с `summary.csv` при этом записывается **`summary.json`** (тот же набор строк; для `--from-summary` удобнее один файл). Отключить JSON: **`--no-summary-json`**.

Только графики из уже готовой сводки (runs не читаются; каталог вывода по умолчанию — тот же, что у файла сводки):

```bash
python3 analyze_tls_results.py --from-summary ../figures/summary.json
# или
python3 analyze_tls_results.py --from-summary ../figures/summary.csv
```

Чтобы PNG ушли в другой каталог, задайте **`--output-dir`**.

Результат:

- `figures/summary.csv` — по группам `chain`, `compression`, `delay_ms`: count, mean, median, std, p95  
- `figures/summary.json` — те же данные (после прогона из runs; опционально исходник для `--from-summary`)
- `figures/tls_handshake_chain_small.png`, `tls_handshake_chain_medium.png`, `tls_handshake_chain_large.png` — по одному графику на цепочку; заголовок вида «Среднее время TLS-рукопожатия для … цепочки сертификатов»; столбцы A–D своими цветами
- `figures/modes_legend.txt` — расшифровка режимов A–D (сжатие, tc netem); флаг `--modes-legend ''` отключает создание файла

## Лаборатория hey/wrk + tshark + mpstat (ideco.local)

См. **[LAB-ideco-wrk-tshark.md](LAB-ideco-wrk-tshark.md)** — **100 ms** netem на сервере, **100 запросов на клиента** через **hey**, доверие к самоподписанному leaf, строгий выход по ошибкам.

- Конфиг: **`lab_wrk_config.json`** (лежит в каталоге скриптов, по умолчанию подставляется без `-c`).
- Оркестратор: `orchestrate_lab_wrk.py`; разбор pcap: `handshake_from_pcap.py`.
- Сервер: `lab_setup_server_certs.sh`; опционально wrk + `wrk_close.lua` при `load.tool` = `wrk`.

```bash
cd experiment-scripts
python3 orchestrate_lab_wrk.py
python3 analyze_tls_results.py ../results/lab_wrk/handshakes_all.csv --output-dir ../figures
```

## Полная матрица (12 файлов × 250 строк)

Для каждой комбинации (3 цепочки × 2 режима сжатия × 2 задержки) выполните отдельный прогон с корректными `--chain`, `--compression`, `--delay-ms`, затем объедините все CSV одним вызовом `analyze_tls_results.py`.

Подробности топологии VPS + Ideco — в [eksperiment-rfc8879-vps-ideco-guide.md](../eksperiment-rfc8879-vps-ideco-guide.md).
