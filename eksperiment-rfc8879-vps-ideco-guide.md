# Полный гайд: эксперимент RFC 8879 (zlib), VPS + Ideco NGFW

Это **единый** документ по основной методике: матрица эксперимента, PKI, **полные** команды `openssl s_server` для режимов A–D и трёх размеров цепочки, `tc netem`, замеры через `curl`/скрипты, таблицы для отчёта. Отдельно лежит только **альтернативный** сценарий без VPS — **[eksperiment-rfc8879-stend.md](eksperiment-rfc8879-stend.md)** (Ideco + ALT в локальной сети).

Документ описывает воспроизводимую методику: сравнение времени TLS 1.3‑рукопожатия **без** сжатия сертификатов и **со сжатием zlib** ([RFC 8879](https://www.rfc-editor.org/rfc/rfc8879.html), алгоритм **1**) при вариации **размера цепочки** и **искусственной задержки** на сервере.

**Зафиксировано для этой работы:**

- Сжатие на сервере в эксперименте — **только zlib** (brotli/zstd в методику не входят).
- Сервер TLS на VPS — **кастомная сборка OpenSSL 3.3.0**: бинарий `/root/openssl-3.3.0/apps/openssl`, **`LD_LIBRARY_PATH=/root/openssl-3.3.0`**.
- PKI — каталог **`/root/sossu_kurs/certs/`**.

Ниже команды — как на VPS; подставьте свой хост (`ideco.theworkpc.com` или другой). Порт сервера — **443**.

---

## Цели и переменные

| Тип | Параметры |
|-----|-----------|
| **Независимые** | (1) размер цепочки: Small / Medium / Large; (2) сжатие: выкл / zlib; (3) задержка на VPS: 0 ms или 50 ms (`tc netem`) |
| **Зависимые** | время TLS‑рукопожатия \(T_{\mathrm{TLS}} \approx\) `time_appconnect − time_connect` (сек); опционально — размеры и тип сообщения в trace |

**Матрица:** \(3 \times 2 \times 2 = 12\) ячеек; в каждой **250** замеров → **3000** строк в общем CSV (или 12 отдельных файлов).

Режимы для сервера:

| Режим | `-cert_comp` | `tc` 50 ms |
|-------|----------------|------------|
| **A** | нет | нет |
| **B** | да | нет |
| **C** | нет | да |
| **D** | да | да |

---

## Ограничения и честность эксперимента

1. **Утяжеление цепочки** повторением одного и того же `int.crt` в `extra_*.crt` — **искусственное увеличение объёма байт**, не модель корректной PKIX в продакшене. Укажите это в отчёте.
2. При смене `-cert_chain` или режима `-cert_comp` **перезапускайте** `openssl s_server`.
3. Правила `tc` **не сохраняются** после перезагрузки VPS — снимайте и добавляйте между этапами.
4. Зафиксируйте версии: OpenSSL на VPS (`openssl version -a`), `curl --version` и OpenSSL на Ideco.

---

## Ideco NGFW на стенде

Развёрнут **Ideco NGFW** (v21, Enterprise demo). Настроена **SSL/TLS-инспекция** HTTPS: к внешним хостам трафик идёт через политику, сертификат сервера для клиента подменяется сертификатом шлюза. Подмену проверяют примерами `curl` в разделе **Проверки** ниже.

---

## Этап 1: PKI и файлы цепочек

Рабочий каталог: `/root/sossu_kurs/certs/`.

### 1.1. Генерация базовых ключей и сертификатов (RSA 4096)

Если файлы уже есть (в т.ч. `leaf.crt`, `int.key`) — генерацию не повторяйте.

```bash
mkdir -p /root/sossu_kurs/certs/
cd /root/sossu_kurs/certs/

openssl req -newkey rsa:4096 -nodes -keyout ca.key -x509 -days 365 -out ca.crt -subj "/CN=RootCA"

openssl req -newkey rsa:4096 -nodes -keyout int.key -out int.csr -subj "/CN=IntermediateCA"
openssl x509 -req -in int.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out int.crt -days 365

openssl req -newkey rsa:4096 -nodes -keyout leaf.key -out leaf.csr -subj "/CN=ideco.theworkpc.com"
openssl x509 -req -in leaf.csr -CA int.crt -CAkey int.key -CAcreateserial -out leaf.crt -days 365
```

Имя в `CN` должно совпадать с тем, по чему стучится клиент Ideco.

### 1.2. Файлы дополнительной цепочки (`extra_*.crt`)

Используется **`int.crt`** из шага выше (если у вас файл назван иначе — поправьте в `cat`).

```bash
cd /root/sossu_kurs/certs/

cat int.crt > extra_small.crt
cat int.crt int.crt int.crt > extra_medium.crt
cat int.crt int.crt int.crt int.crt int.crt int.crt > extra_large.crt

wc -c extra_small.crt extra_medium.crt extra_large.crt
```

Занесите байты в **Таблицу 1** отчёта.

---

## Этап 2: Сервер TLS на VPS — OpenSSL 3.3.0

Использовать **одну** сборку для всех прогонов; меняются файл `-cert_chain`, флаг `-cert_comp` и наличие `tc`.

### 2.1. Сборка из исходников (если уже сделано — пропустить)

```bash
cd /root
wget https://github.com/openssl/openssl/releases/download/openssl-3.3.0/openssl-3.3.0.tar.gz
tar -zxf openssl-3.3.0.tar.gz
cd openssl-3.3.0
./config enable-brotli enable-zstd enable-zlib
make -j$(nproc)
```

### 2.2. Переменные и проверка опции `cert_comp`

```bash
export LD_LIBRARY_PATH=/root/openssl-3.3.0
export OPENSSL_BIN=/root/openssl-3.3.0/apps/openssl

sudo LD_LIBRARY_PATH=/root/openssl-3.3.0 "$OPENSSL_BIN" s_server -help 2>&1 | grep -i cert_comp
```

### 2.3. Смысл аргументов `openssl s_server`

- **`-cert`** — PEM конечного (серверного) сертификата.
- **`-key`** — закрытый ключ **этого** конечного сертификата (должен быть парой к `-cert`). В примерах ниже: `leaf.crt` и `int.key` — как на вашем стенде; при смене PKI обновите оба согласованно.
- **`-cert_chain`** — PEM с **дополнительными** сертификатами (обычно промежуточные УЦ), которые сервер шлёт **после** leaf. Здесь — `extra_*.crt` с утяжелённым содержимым для эксперимента.

Три аргумента **не дублируют** друг друга: конечный сертификат + ключ отдельно, «хвост» цепочки — в `-cert_chain`.

- **`-cert_comp`** — включение сжатия сертификата на сервере; алгоритм (в т.ч. zlib) согласуется по RFC 8879. **Не** подставляйте отдельным токеном `brotli` после `-cert_comp` — в вашей сборке будет `Extra option: "brotli"`. Запись **`[-cert_comp zlib]`** в старых текстах — условное «опционально в квадратных скобках» в markdown, **не** буквальная команда shell.

### 2.4. Эмуляция задержки на VPS (`tc`) — до режимов C и D

Узнайте интерфейс в сторону клиента Ideco:

```bash
ip -br a
# или
ip route get ИЗВЕСТНЫЙ_IP_IDECO_WAN
```

Включить **50 ms** (нужно для C и D):

```bash
sudo tc qdisc add dev ИМЯ_IFACE root netem delay 50ms
tc qdisc show dev ИМЯ_IFACE
```

Выключить после этапа замеров:

```bash
sudo tc qdisc del dev ИМЯ_IFACE root netem
```

---

### 2.5. Полные команды: малая цепочка (`extra_small.crt`)

Перед каждым сменой режима остановите предыдущий `s_server` (Ctrl+C).

#### Режим A — без сжатия, без `tc`

```bash
cd /root/sossu_kurs/certs/
sudo LD_LIBRARY_PATH=/root/openssl-3.3.0 /root/openssl-3.3.0/apps/openssl s_server \
  -accept 443 \
  -cert /root/sossu_kurs/certs/leaf.crt \
  -key /root/sossu_kurs/certs/int.key \
  -cert_chain /root/sossu_kurs/certs/extra_small.crt \
  -tls1_3 \
  -www -quiet
```

#### Режим B — с `-cert_comp`, без `tc`

```bash
cd /root/sossu_kurs/certs/
sudo LD_LIBRARY_PATH=/root/openssl-3.3.0 /root/openssl-3.3.0/apps/openssl s_server \
  -accept 443 \
  -cert /root/sossu_kurs/certs/leaf.crt \
  -key /root/sossu_kurs/certs/int.key \
  -cert_chain /root/sossu_kurs/certs/extra_small.crt \
  -tls1_3 \
  -cert_comp \
  -www -quiet
```

#### Режим C — без сжатия, с `tc` 50 ms

Сначала включить `tc` (п. 2.4), затем:

```bash
cd /root/sossu_kurs/certs/
sudo LD_LIBRARY_PATH=/root/openssl-3.3.0 /root/openssl-3.3.0/apps/openssl s_server \
  -accept 443 \
  -cert /root/sossu_kurs/certs/leaf.crt \
  -key /root/sossu_kurs/certs/int.key \
  -cert_chain /root/sossu_kurs/certs/extra_small.crt \
  -tls1_3 \
  -www -quiet
```

После замеров — снять `tc`.

#### Режим D — с `-cert_comp`, с `tc` 50 ms

Сначала включить `tc`, затем:

```bash
cd /root/sossu_kurs/certs/
sudo LD_LIBRARY_PATH=/root/openssl-3.3.0 /root/openssl-3.3.0/apps/openssl s_server \
  -accept 443 \
  -cert /root/sossu_kurs/certs/leaf.crt \
  -key /root/sossu_kurs/certs/int.key \
  -cert_chain /root/sossu_kurs/certs/extra_small.crt \
  -tls1_3 \
  -cert_comp \
  -www -quiet
```

После замеров — снять `tc`.

Если **`openssl s_server -help`** показывает явную форму вроде `-cert_comp zlib`, её можно использовать — главное, чтобы строка совпадала со всеми прогонами.

---

### 2.6. Средняя цепочка

Те же режимы **A–D**; во всех командах замените одну строку на:

```text
-cert_chain /root/sossu_kurs/certs/extra_medium.crt
```

---

### 2.7. Тяжёлая цепочка

Те же режимы **A–D**; замените на:

```text
-cert_chain /root/sossu_kurs/certs/extra_large.crt
```

---

### 2.8. Оценка коэффициента сжатия (опционально, таблица 1 в курсовой)

```bash
echo | openssl s_client -connect ideco.theworkpc.com:443 -tls1_3 -servername ideco.theworkpc.com -trace 2>&1 | grep -iE 'Certificate|CompressedCertificate'
```

Для точных размеров байт удобнее одна запись в Wireshark по `tcpdump`.

---

## Этап 3: Клиент Ideco NGFW — метрики

HTTPS к вашему хосту (или IP с `-k`).

Предпочтительно один раз разогреть DNS или использовать IP в URL, чтобы не смешивать с метрикой TLS.

Пример цикла вручную (для финальной статистики лучше скрипт на **250** прогонов):

```bash
for i in $(seq 1 250); do
  curl -k -w "%{time_connect} %{time_appconnect}\n" -o /dev/null -s "https://ideco.theworkpc.com/" \
    | awk '{printf "TLS Handshake: %.2f ms\n", ($2 - $1) * 1000}'
done
```

Скрипт (из каталога репозитория на машине с Python и `curl`):

```bash
cd experiment-scripts
python3 collect_tls_metrics.py --url "https://IDE_IP_OR_NAME/" --runs 250 --sleep-ms 150 \
  --chain large --compression off --delay-ms 0 \
  --output ../runs/large_off_delay0.csv \
  --stderr-log ../runs/large_off_delay0.err.log
```

Повторите для каждой комбинации `chain` × `compression` × `delay_ms`. Параметры `--delay-ms` и `--chain` — **метки в CSV**; реальную задержку на VPS включаете вручную (как в этапе 2).

Примеры имён файлов:

- Режим A, small, без задержки: `small_A_off_delay0.csv`
- Режим B: `--compression zlib` (метка: на сервере был `-cert_comp`), например `small_B_zlib_delay0.csv`
- Режим C: `--delay-ms 50`, сервер без `-cert_comp`, `small_C_off_delay50.csv`
- Режим D: `--delay-ms 50`, `--compression zlib`, `small_D_zlib_delay50.csv`

Обработка:

```bash
python3 analyze_tls_results.py ../runs/*.csv --output-dir ../figures --summary summary.csv
```

---

## Этап 4: Повтор при включённом `tc`

Если этап 3 уже выполнен без задержки, на VPS включите **`tc`** (п. 2.4), оставьте те же режимы `s_server`, выполните ещё **250** замеров на ячейку с меткой `delay_ms=50`.

Не забудьте снять `tc` после тестов:

```bash
sudo tc qdisc del dev ИМЯ_IFACE root netem
```

---

## Структура результатов для курсовой

### Таблица 1: Эффективность компрессии zlib

| Уровень цепочки | Исходный размер цепочки (байт) | Сжатый размер (байт) | Ratio |
|-----------------|--------------------------------|----------------------|-------|
| Small | ___ | ___ | ___ |
| Medium | ___ | ___ | ___ |
| Large | ___ | ___ | ___ |

### Таблица 2: Время TLS‑рукопожатия

| Уровень цепочки | Без сжатия, 0 ms | С zlib, 0 ms | Без сжатия, 50 ms | С zlib, 50 ms |
|-----------------|------------------|--------------|-------------------|---------------|
| Small | ___ ms | ___ ms | ___ ms | ___ ms |
| Medium | ___ ms | ___ ms | ___ ms | ___ ms |
| Large | ___ ms | ___ ms | ___ ms | ___ ms |

Числа — из `analyze_tls_results.py` (`summary.csv`).

---

## Проверки: подмена сертификата, zlib на проводе, дамп

### Примеры issuer через Ideco (с пользовательской машины ALT и т.п.)

```text
curl -v https://ya.ru 2>&1 | grep -i "issuer"
curl -v -k https://ваш-ip-или-хост 2>&1 | grep -i "issuer"
```

### Клиент с `-cert_comp` и trace

```bash
echo | openssl s_client -connect ideco.theworkpc.com:443 -tls1_3 \
  -cert_comp \
  -servername ideco.theworkpc.com -trace 2>&1 | grep -iE 'CompressedCertificate|Certificate'
```

При согласованном сжатии ожидайте **`CompressedCertificate`**.

### tcpdump

```bash
sudo tcpdump -i ИМЯ_IFACE port 443 -w upstream.pcap
```

В Wireshark в ClientHello — расширение **compress_certificate** (тип 27).

---

## Автоматизация

- [`experiment-scripts/collect_tls_metrics.py`](experiment-scripts/collect_tls_metrics.py)
- [`experiment-scripts/analyze_tls_results.py`](experiment-scripts/analyze_tls_results.py)
- [`experiment-scripts/requirements.txt`](experiment-scripts/requirements.txt)

---

## Краткий чеклист матрицы

1. Сервер **off**, chain **small**, **tc выкл** → **250** замеров → CSV  
2. Сервер с **`-cert_comp`**, chain **small**, **tc выкл** → **250** замеров  
3. Повторить для **medium**, **large** при **tc выкл**  
4. Включить **tc 50 ms**, повторить все **6** комбинаций цепочка × сжатие (каждая × **250**)  
5. Объединить CSV → `analyze_tls_results.py` → таблицы и `figures/*.png`

---

*Обновление: репозиторий проекта курсовой.*
