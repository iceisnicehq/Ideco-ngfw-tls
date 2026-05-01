# Лаборатория: hey/wrk + tcpdump/tshark + mpstat, ideco.local

Методика: нагрузка **`hey`** (по умолчанию **100 запросов на каждого клиента**, `-disable-keepalive` — новые соединения и полные рукопожатия) с трёх клиентов через **Ideco NGFW** к **`ideco.local`**; эмуляция канала — **`tc netem delay 100ms`** на **`enp0s3`** сервера (фаза с ненулевой задержкой); замер TLS — **pcap + tshark**; нагрузка на CPU шлюза — **`mpstat`**.

Альтернатива в конфиге: **`load.tool": "wrk"`** (режим длительности, см. `wrk_fallback`).

## Топология и имена

| Узел | IP / имя | Интерфейс захвата / tc |
|------|-----------|-------------------------|
| Клиенты | `10.0.10.10`, `10.0.10.20`, `10.0.10.30` | `enp0s3` (`tcpdump -i enp0s3`) |
| Сервер TLS | `ideco.local` → **`192.168.1.181`** | `enp0s3` (`tc qdisc … dev enp0s3`) |
| Шлюз | Ideco NGFW (см. `lab_wrk_config.json`) | SSH для `mpstat` |

На **всех клиентах** и на машине оркестратора в `/etc/hosts`:

```text
192.168.1.181 ideco.local
```

**SSL-инспекция:** только **`https://ideco.local/`** (не по IP).

## Самоподписанный leaf и доверие на клиентах

**`openssl s_server`** отдаёт ваш **`leaf.crt`**. Утилита **`hey`** проверяет цепочку так же, как клиент TLS: при самоподписанном сертификате запросы **упадут**, пока leaf **не доверен** на машине-клиенте.

В **`lab_wrk_config.json`** по умолчанию включено **`"distribute_trusted_leaf": true`**: перед фазами оркестратор снимает `leaf.crt` с сервера и ставит его в хранилище доверенных УЦ на каждом клиенте (`update-ca-certificates` или `update-ca-trust`). Если ваша ОС использует другой механизм — один раз настройте доверие вручную или отключите флаг и импортируйте сертификат сами.

После этого **hey** к `https://ideco.local/` должен проходить без отключения проверки.

## 1. Сертификаты на ideco.local

Публичные файлы в [`../real_certs/`](../real_certs/) без закрытого ключа leaf. Нужен **свой leaf** для `ideco.local` (CN/SAN = `ideco.local`) и файлы цепочек для **`-cert_chain`**.

На сервере под root:

```bash
cd /путь/к/experiment-scripts
bash lab_setup_server_certs.sh --dir /opt/lab-tls --fqdn 'ideco.local'
mkdir -p /opt/lab-tls/chains
cp ../real_certs/apple.com.crt     /opt/lab-tls/chains/small.pem
cp ../real_certs/google.com.crt    /opt/lab-tls/chains/medium.pem
cp ../real_certs/microsoft.com.crt /opt/lab-tls/chains/large.pem
```

Пути должны совпадать с **`chain_remote_paths`** в **`lab_wrk_config.json`**.

### Примеры s_server и tc

```bash
openssl s_server -accept 443 -www -tls1_3 \
  -cert /opt/lab-tls/leaf.crt -key /opt/lab-tls/leaf.key \
  -cert_chain /opt/lab-tls/chains/small.pem \
  -no_ticket
```

С задержкой **100 ms** на сервере:

```bash
tc qdisc del dev enp0s3 root 2>/dev/null || true
tc qdisc add dev enp0s3 root netem delay 100ms
```

## 2. Конфиг

Рабочий файл: **[`lab_wrk_config.json`](lab_wrk_config.json)** (хосты, **`ssh_password`**, цепочки, **`load`** с числом запросов, фазы **`delay_ms`: 0 и 100**).

Вместо **`ssh_password`** можно задать **`auth_env`** и положить пароль в переменную окружения (имя из `auth_env`).

## 3. Зависимости

- Машина оркестратора: **Python 3**, **sshpass**, **ssh**, **scp**, **tshark** (разбор pcap после скачивания).
- Клиенты: **tcpdump**, **hey** (рекомендуется путь из `load.hey_bin`), опционально **wrk**.
- Сервер: **openssl** с **s_server** и **tc**.

## 4. Запуск

```bash
cd experiment-scripts
python3 orchestrate_lab_wrk.py
```

По умолчанию читается **`lab_wrk_config.json`** рядом со скриптом. Другой файл: **`python3 orchestrate_lab_wrk.py -c /путь/конфиг.json`**.

При **любой** ошибке SSH, **hey**, **scp**, пустом pcap или **tshark** процесс завершается с ненулевым кодом.

Матрица фаз: цепочка × **off/zlib** × задержка **0 / 100 ms**. Результаты: **`results_dir`** (по умолчанию `../results/lab_wrk`), **`handshakes_all.csv`**.

Только объединить уже собранные CSV:

```bash
python3 orchestrate_lab_wrk.py --merge-only
```

## 5. Разбор pcap и графики

```bash
python3 handshake_from_pcap.py capture.pcap \
  --client-ip 10.0.10.10 \
  --chain small --compression off --delay-ms 100 \
  --source-client c10 --wrk-url 'https://ideco.local/' \
  -o handshakes.csv
```

```bash
python3 analyze_tls_results.py ../results/lab_wrk/handshakes_all.csv --output-dir ../figures
```

## 6. Метрика в tshark

От **SYN клиента** (порт 443) до первого **TLS Application Data (тип 23)** от пира с `ip.src != client_ip` в том же `tcp.stream`.

## 7. Пароли и репозиторий

В проекте лежит заполненный **`lab_wrk_config.json`** под ваш стенд. Не выкладывайте его в открытый git с реальными паролями без необходимости; для другой среды отредактируйте хосты и **`ssh_password`**.
