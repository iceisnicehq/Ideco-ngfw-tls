# Запуск эксперимента на ALT Linux (ваша машина)

Ниже — только то, что нужно вам: какие файлы положить на ALT и как запустить автоматический цикл по SSH.

Предполагается:

- С ALT уже ходит **`ssh root@ideco.theworkpc.com`** на VPS и **`ssh admin@10.0.10.1`** на Ideco NGFW **без пароля** (ключ в `~/.ssh/`).
- На VPS уже собран OpenSSL, лежат сертификаты в `/root/sossu_kurs/certs/` как в **`remote_config.json`**.
- Если SSH на VPS идёт **не** на `ideco.theworkpc.com`, а на IP или другой хост — откройте **`experiment-scripts/remote_config.json`** и поменяйте строку **`vps_ssh`**.

---

## 1. Какие файлы скопировать на ALT

Создайте на ALT каталог, например:

```bash
mkdir -p ~/Ideco-NGFW-tls/experiment-scripts ~/Ideco-NGFW-tls/runs
```

С хоста с проектом скопируйте **целиком папку** `experiment-scripts/` (со всеми `.py` и **`remote_config.json`**):

Минимально нужны файлы:

| Файл | Зачем |
|------|--------|
| `collect_tls_metrics.py` | Общая функция замеров через curl |
| `collect_tls_abcd.py` | Ручной интерактивный A–D без SSH |
| `orchestrate_remote.py` | Автоматизация по SSH |
| `analyze_tls_results.py` | Сводка и графики после замеров |
| `requirements.txt` | Зависимости Python (обычно только stdlib + то же что в файле) |
| **`remote_config.json`** | Ваши адреса и пути (уже с вашими хостами; правьте при необходимости) |

Результаты по умолчанию пишутся в **`../runs`** относительно каталога скриптов — при структуре выше это будет **`~/Ideco-NGFW-tls/runs`**.

Пример копирования с машины, где лежит репозиторий (подставьте свой путь):

```bash
scp -r /путь/к/Ideco-NGFW-tls/experiment-scripts user@alt:/home/user/Ideco-NGFW-tls/
```

Или через флешку / общую папку — главное, чтобы на ALT были те же файлы.

---

## 2. Зависимости на ALT

Нужны **`python3`** и **`curl`** в `PATH`:

```bash
python3 --version
curl --version
```

Дополнительные пакеты Python для этих скриптов не обязательны (используется стандартная библиотека). При желании:

```bash
cd ~/Ideco-NGFW-tls/experiment-scripts
pip3 install -r requirements.txt
```

---

## 3. Проверка SSH с ALT

```bash
ssh -o BatchMode=yes root@ideco.theworkpc.com 'echo OK_vps'
ssh -o BatchMode=yes admin@10.0.10.1 'echo OK_ideco'
```

Если спрашивает пароль — настройте ключ (`ssh-copy-id`) или добавьте в **`remote_config.json`** в массив **`ssh_extra_args`** путь к ключу, например:

```json
"ssh_extra_args": ["-o", "BatchMode=yes", "-i", "/home/ВЫ/.ssh/id_rsa"]
```

---

## 4. Правка `remote_config.json` под себя

Откройте **`experiment-scripts/remote_config.json`** и при необходимости измените:

- **`vps_ssh`** — куда заходить для управления `openssl s_server` и `tc` (часто это тот же VPS, что обслуживает ваш тестовый HTTPS).
- **`https_url`** — URL для curl с ALT (трафик должен идти через Ideco к вашему серверу, как в методике).
- **`chains_to_run`** — например `["small"]` или `["small","medium","large"]`.
- **`run_ideco_trace`** — `false`, если на Ideco нет нормального `openssl` в SSH-сессии.

---

## 5. Запуск автоматизации

```bash
cd ~/Ideco-NGFW-tls/experiment-scripts
python3 orchestrate_remote.py -c remote_config.json
```

По умолчанию вывод **подробный**: время, этапы VPS / Ideco / локальные curl, код возврата SSH, прогресс curl каждые **25** запросов (число задаётся **`curl_progress_every`** в конфиге).

Тихий режим (меньше текста):

```bash
python3 orchestrate_remote.py -c remote_config.json --quiet
```

Показать полный bash-скрипт, который уходит на VPS (длинные блоки):

```bash
python3 orchestrate_remote.py -c remote_config.json --dump-remote-scripts
```

Проверка без SSH и без curl:

```bash
python3 orchestrate_remote.py -c remote_config.json --dry-run
```

---

## 6. После замеров — анализ

```bash
cd ~/Ideco-NGFW-tls/experiment-scripts
python3 analyze_tls_results.py ../runs/*.csv --output-dir ../figures --summary ../figures/summary.csv
```

---

## Зачем был «шаблон» конфига раньше

Отдельный `example.json` нужен был только как образец для репозитория. Для вас достаточно одного **`remote_config.json`** с вашими адресами — он в проекте уже лежит; меняйте его под стенд без копирования шаблона.
