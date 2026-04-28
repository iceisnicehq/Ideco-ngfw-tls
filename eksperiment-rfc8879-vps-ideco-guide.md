# Полный гайд: эксперимент RFC 8879 (zlib), VPS + Ideco NGFW

Это **единый** документ по методике: матрица эксперимента, PKI, **полные** команды `openssl s_server` для режимов A–D и трёх размеров цепочки, `tc netem`, замеры через `curl`/скрипты, таблицы для отчёта.

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
4. Зафиксируйте версии: OpenSSL на VPS (`openssl version -a`), на машине замеров — `curl --version` и OpenSSL (ALT и/или консоль Ideco, где запускаете скрипт и `s_client`).

---

## Ideco NGFW на стенде

Развёрнут **Ideco NGFW** (v21, Enterprise demo). Настроена **SSL/TLS-инспекция** HTTPS: к внешним хостам трафик идёт через политику, сертификат сервера для клиента подменяется сертификатом шлюза. Подмену проверяют примерами `curl` в разделе **Проверки** ниже.

---

## Этап 1: PKI и файлы цепочек

Рабочий каталог: `/root/sossu_kurs/certs/`.

### 1.1. Генерация базовых ключей и сертификатов (RSA 4096)

Если файлы уже есть (в т.ч. `leaf.crt`, **`leaf.key`** — ключ именно к конечному сертификату) — генерацию не повторяйте.

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
- **`-key`** — закрытый ключ **этого** конечного сертификата (должен быть парой к `-cert`). Для **`leaf.crt`** это **`leaf.key`** (ключ, которым подписывался CSR leaf). **`int.key`** — ключ промежуточного УЦ; он подходит к **`int.crt`**, но **не** к `leaf.crt`, иначе OpenSSL выдаст `key values mismatch`.
- **`-cert_chain`** — PEM с **дополнительными** сертификатами (обычно промежуточные УЦ), которые сервер шлёт **после** leaf. Здесь — `extra_*.crt` с утяжелённым содержимым для эксперимента.

Три аргумента **не дублируют** друг друга: конечный сертификат + ключ отдельно, «хвост» цепочки — в `-cert_chain`.

- **`-cert_comp`** — включение сжатия сертификата на сервере; алгоритм (в т.ч. zlib) согласуется по RFC 8879. **Не** подставляйте отдельным токеном `brotli` после `-cert_comp` — в вашей сборке будет `Extra option: "brotli"`. Запись **`[-cert_comp zlib]`** в старых текстах — условное «опционально в квадратных скобках» в markdown, **не** буквальная команда shell.

### 2.4. Интерфейс для `tc` и команда `ip route get`

**Зачем это нужно.** Правило `tc qdisc … dev ens3` вешается на **локальный сетевой интерфейс Linux на VPS** (например `eth0`, `ens3`). Через него уходит ответный трафик к клиентам в Интернете.

**Что делает `ip route get АДРЕС`.** Показывает, **через какой интерфейс и шлюз** ядро отправит пакет к указанному IP. Это способ узнать **`dev`** для вашего случая.

**Если Ideco в VirtualBox (bridged), клиент за NAT.** Для VPS ваш браузер/Ideco всё равно видны как соединение с **публичного IP вашего роутера**; частный адрес ВМ до VPS не доходит. На VPS это не ломает выбор интерфейса: исходящий интернет‑интерфейс VPS обычно один и тот же (часто тот же, что и для `default`‑маршрута).

Примеры на VPS:

```bash
ip -br link show
ip route show default
ip route get 8.8.8.8
```

В строке будет что‑то вроде `dev eth0 src …` — **`eth0`** и есть кандидат на **`ens3`** для `tc`. Если есть несколько интерфейсов — берите тот, через который реально уходит трафик к вашему тестовому клиенту (часто совпадает с интерфейсом по умолчанию).

Перед режимами **A и B** правило задержки **не нужно**, его быть не должно. Проверка:

```bash
tc qdisc show dev ens3
```

Если там уже есть `netem` от прошлых прогонов — снимите:

```bash
sudo tc qdisc del dev ens3 root netem
```

Для режимов **C и D** включите задержку **до** запуска `s_server` и **до** замеров:

```bash
sudo tc qdisc add dev ens3 root netem delay 50ms
tc qdisc show dev ens3
```

После того как закончили замеры для этой ячейки (и остановили `s_server`), **обязательно** снимите `tc`, чтобы следующая ячейка (A или B) не измерялась «с хвостом» задержки:

```bash
sudo tc qdisc del dev ens3 root netem
```

**Итого по `tc`:** включили только перед **C/D**, выключили сразу после **C/D**. Для **A/B** — всегда без `tc`.

---

### 2.5. Полные команды: малая цепочка (`extra_small.crt`)

Перед каждым сменой режима остановите предыдущий `s_server` (Ctrl+C).

#### Режим A — без сжатия, без `tc`

```bash
cd /root/sossu_kurs/certs/
sudo LD_LIBRARY_PATH=/root/openssl-3.3.0 /root/openssl-3.3.0/apps/openssl s_server \
  -accept 443 \
  -cert /root/sossu_kurs/certs/leaf.crt \
  -key /root/sossu_kurs/certs/leaf.key \
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
  -key /root/sossu_kurs/certs/leaf.key \
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
  -key /root/sossu_kurs/certs/leaf.key \
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
  -key /root/sossu_kurs/certs/leaf.key \
  -cert_chain /root/sossu_kurs/certs/extra_small.crt \
  -tls1_3 \
  -cert_comp \
  -www -quiet
```

После замеров — снять `tc`.

Если **`openssl s_server -help`** показывает явную форму вроде `-cert_comp zlib`, её можно использовать — главное, чтобы строка совпадала со всеми прогонами.

---

### 2.6. Полные команды: средняя цепочка (`extra_medium.crt`)

Отличие от §2.5 только в строке `-cert_chain`.

#### Режим A — без сжатия, без `tc`

```bash
cd /root/sossu_kurs/certs/
sudo LD_LIBRARY_PATH=/root/openssl-3.3.0 /root/openssl-3.3.0/apps/openssl s_server \
  -accept 443 \
  -cert /root/sossu_kurs/certs/leaf.crt \
  -key /root/sossu_kurs/certs/leaf.key \
  -cert_chain /root/sossu_kurs/certs/extra_medium.crt \
  -tls1_3 \
  -www -quiet
```

#### Режим B — с `-cert_comp`, без `tc`

```bash
cd /root/sossu_kurs/certs/
sudo LD_LIBRARY_PATH=/root/openssl-3.3.0 /root/openssl-3.3.0/apps/openssl s_server \
  -accept 443 \
  -cert /root/sossu_kurs/certs/leaf.crt \
  -key /root/sossu_kurs/certs/leaf.key \
  -cert_chain /root/sossu_kurs/certs/extra_medium.crt \
  -tls1_3 \
  -cert_comp \
  -www -quiet
```

#### Режим C — без сжатия, с `tc` 50 ms

Сначала включить `tc` (п. 2.4), затем сервер:

```bash
cd /root/sossu_kurs/certs/
sudo LD_LIBRARY_PATH=/root/openssl-3.3.0 /root/openssl-3.3.0/apps/openssl s_server \
  -accept 443 \
  -cert /root/sossu_kurs/certs/leaf.crt \
  -key /root/sossu_kurs/certs/leaf.key \
  -cert_chain /root/sossu_kurs/certs/extra_medium.crt \
  -tls1_3 \
  -www -quiet
```

После замеров — снять `tc`.

#### Режим D — с `-cert_comp`, с `tc` 50 ms

Сначала включить `tc`, затем сервер:

```bash
cd /root/sossu_kurs/certs/
sudo LD_LIBRARY_PATH=/root/openssl-3.3.0 /root/openssl-3.3.0/apps/openssl s_server \
  -accept 443 \
  -cert /root/sossu_kurs/certs/leaf.crt \
  -key /root/sossu_kurs/certs/leaf.key \
  -cert_chain /root/sossu_kurs/certs/extra_medium.crt \
  -tls1_3 \
  -cert_comp \
  -www -quiet
```

После замеров — снять `tc`.

---

### 2.7. Полные команды: тяжёлая цепочка (`extra_large.crt`)

Те же режимы **A–D**; во всех блоках ниже используется `-cert_chain …/extra_large.crt`.

#### Режим A — без сжатия, без `tc`

```bash
cd /root/sossu_kurs/certs/
sudo LD_LIBRARY_PATH=/root/openssl-3.3.0 /root/openssl-3.3.0/apps/openssl s_server \
  -accept 443 \
  -cert /root/sossu_kurs/certs/leaf.crt \
  -key /root/sossu_kurs/certs/leaf.key \
  -cert_chain /root/sossu_kurs/certs/extra_large.crt \
  -tls1_3 \
  -www -quiet
```

#### Режим B — с `-cert_comp`, без `tc`

```bash
cd /root/sossu_kurs/certs/
sudo LD_LIBRARY_PATH=/root/openssl-3.3.0 /root/openssl-3.3.0/apps/openssl s_server \
  -accept 443 \
  -cert /root/sossu_kurs/certs/leaf.crt \
  -key /root/sossu_kurs/certs/leaf.key \
  -cert_chain /root/sossu_kurs/certs/extra_large.crt \
  -tls1_3 \
  -cert_comp \
  -www -quiet
```

#### Режим C — без сжатия, с `tc` 50 ms

Сначала включить `tc`, затем сервер:

```bash
cd /root/sossu_kurs/certs/
sudo LD_LIBRARY_PATH=/root/openssl-3.3.0 /root/openssl-3.3.0/apps/openssl s_server \
  -accept 443 \
  -cert /root/sossu_kurs/certs/leaf.crt \
  -key /root/sossu_kurs/certs/leaf.key \
  -cert_chain /root/sossu_kurs/certs/extra_large.crt \
  -tls1_3 \
  -www -quiet
```

После замеров — снять `tc`.

#### Режим D — с `-cert_comp`, с `tc` 50 ms

Сначала включить `tc`, затем сервер:

```bash
cd /root/sossu_kurs/certs/
sudo LD_LIBRARY_PATH=/root/openssl-3.3.0 /root/openssl-3.3.0/apps/openssl s_server \
  -accept 443 \
  -cert /root/sossu_kurs/certs/leaf.crt \
  -key /root/sossu_kurs/certs/leaf.key \
  -cert_chain /root/sossu_kurs/certs/extra_large.crt \
  -tls1_3 \
  -cert_comp \
  -www -quiet
```

После замеров — снять `tc`.

---

### 2.8. Одна ячейка матрицы: порядок действий (строго по шагам)

Цель ячейки: при зафиксированном режиме сервера (**A**, **B**, **C** или **D**) и размере цепочки (**small** / **medium** / **large**) собрать **250** строк CSV замеров и при необходимости один раз посмотреть trace для таблицы сжатия.

Выполняйте на **цепочке от режима A для данного размера цепочки к D**, каждый раз целиком ниже.

| Шаг | Где | Действие |
|-----|-----|----------|
| **1** | **VPS** | Для режимов **A** и **B**: убедиться, что **`tc` выключен** (`tc qdisc del …`, см. п. 2.4). Для **C** и **D**: **включить** `tc netem delay 50 ms` на нужном интерфейсе. |
| **2** | **VPS** | Запустить ровно ту команду `s_server`, которая соответствует текущей ячейке (§2.5 / §2.6 / §2.7). Оставить процесс работать. |
| **3** | **Ideco NGFW** (консоль с `openssl`) | Один раз выполнить проверку типа сообщения и строк для таблицы сжатия (ниже — пример). Это **не** замена **250** прогонам; только контроль для отчёта. |
| **4** | **ALT** (или другая машина с Python/`curl`, откуда реально ходите HTTPS через политику Ideco к VPS) | Запустить **`collect_tls_metrics.py`** на **250** прогонов с правильными `--chain`, `--compression`, `--delay-ms` и именем CSV (см. этап 3). |
| **5** | **VPS** | Остановить `s_server` (Ctrl+C). |
| **6** | **VPS** | Если ячейка была **C** или **D** — **снять** `tc` (`tc qdisc del …`), прежде чем переходить к ячейке **без** задержки. |

**Проверка на Ideco NGFW (один раз на ячейку, пока работает нужный `s_server`):**

```bash
echo | openssl s_client -connect ideco.theworkpc.com:443 -tls1_3 -trace 2>&1 \
  | grep -A 3 -iE "CompressedCertificate|Certificate, Length"
```

Подставьте своё имя хоста. При ошибке сертификата добавьте при необходимости `-servername ideco.theworkpc.com` и/или проверку в духе `-verify_return_error` по ситуации; для учебного стенда иногда нужен `-k` на стороне `curl`, для `s_client` — доверенный CA или явная политика проверки.

Для чисел в **таблицу 1** курсовой точнее смотреть размеры в **Wireshark** по дампу (`tcpdump` на VPS), если нужны байты «на проводе».

---

### 2.9. Кратко: зачем был раздел «Этап 4» раньше

Раньше повтор при `tc` выносился отдельным блоком и создавал впечатление «сначала выключить tc, потом замерять». По методике всё проще: **для каждой ячейки C или D** вы включаете `tc` перед сервером и замерами и **снимаете сразу после** этой ячейки (шаги 1 и 6 выше). Отдельного «глобального» этапа не нужно.

---

## Этап 3: Замеры времени TLS на ALT (скрипт `collect_tls_metrics.py`)

HTTPS запросы должны идти на ваш тестовый хост (**например** `https://ideco.theworkpc.com/`) так же, как в эксперименте: с клиента за Ideco NGFW, чтобы совпадали инспекция TLS и политика.

Подставьте путь к репозиторию на ALT и свой URL:

```bash
cd /путь/к/Ideco-NGFW-tls/experiment-scripts
python3 collect_tls_metrics.py \
  --url "https://ideco.theworkpc.com/" \
  --runs 250 \
  --sleep-ms 150 \
  --chain small \
  --compression off \
  --delay-ms 0 \
  --insecure-k \
  --output ../runs/small_A_off_delay0.csv \
  --stderr-log ../runs/small_A_off_delay0.err.log
```

- Параметры `--chain` (`small` / `medium` / `large`), `--compression` (`off` или `zlib` — метка того, что на VPS был режим без или с `-cert_comp`) и `--delay-ms` (`0` или `50`) должны **совпадать** с тем, что реально включено на VPS в этой ячейке.  
- **`--delay-ms`** только **подпись в CSV**; реальную задержку включаете на VPS через `tc` (п. 2.4).

Примеры имён файлов при той же нумерации, что режимы **A–D**:

| Ячейка | Пример имени CSV | Заметки к параметрам скрипта |
|--------|------------------|--------------------------------|
| Small, A | `small_A_off_delay0.csv` | `--compression off`, `--delay-ms 0` |
| Small, B | `small_B_zlib_delay0.csv` | `--compression zlib`, `--delay-ms 0` |
| Small, C | `small_C_off_delay50.csv` | `--compression off`, `--delay-ms 50`, на VPS `tc` включён |
| Small, D | `small_D_zlib_delay50.csv` | `--compression zlib`, `--delay-ms 50`, на VPS `tc` включён |

Для **medium** и **large** меняйте префикс (`medium_…`, `large_…`) и `--chain`.

Ручной цикл на 250 запросов (если без Python), с ALT:

```bash
for i in $(seq 1 250); do
  curl -k -w "%{time_connect} %{time_appconnect}\n" -o /dev/null -s "https://ideco.theworkpc.com/" \
    | awk '{printf "TLS Handshake: %.2f ms\n", ($2 - $1) * 1000}'
done
```

Обработка после сбора всех CSV:

```bash
cd experiment-scripts
python3 analyze_tls_results.py ../runs/*.csv --output-dir ../figures --summary summary.csv
```

Предпочтительно один раз «разогреть» DNS или зафиксировать IP в `/etc/hosts` на ALT, чтобы не смешивать в выборке задержки резолва.

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

Для разового контроля при сборе метрик см. строку trace в §**2.8** (Ideco NGFW). Дополнительно с машины с OpenSSL:

```bash
echo | openssl s_client -connect ideco.theworkpc.com:443 -tls1_3 \
  -cert_comp \
  -servername ideco.theworkpc.com -trace 2>&1 | grep -iE 'CompressedCertificate|Certificate'
```

При согласованном сжатии ожидайте **`CompressedCertificate`**.

### tcpdump

```bash
sudo tcpdump -i ens3 port 443 -w upstream.pcap
```

В Wireshark в ClientHello — расширение **compress_certificate** (тип 27).

---

## Автоматизация

- [`experiment-scripts/collect_tls_metrics.py`](experiment-scripts/collect_tls_metrics.py)
- [`experiment-scripts/analyze_tls_results.py`](experiment-scripts/analyze_tls_results.py)
- [`experiment-scripts/requirements.txt`](experiment-scripts/requirements.txt)

---

## Краткий чеклист матрицы

1. На каждую из **12** ячеек (3 цепочки × 4 режима **A–D**) выполняйте подряд шаги **1–6** из §**2.8**: VPS (`tc` только для **C/D**) → один раз trace на **Ideco** → **250** замеров скриптом на **ALT** → остановка `s_server` → для **C/D** снять `tc`.  
2. Удобный порядок: для **extra_small** пройти **A → B → C → D**, затем то же для **extra_medium**, затем для **extra_large**.  
3. В конце всех CSV — **`analyze_tls_results.py`** → таблицы и `figures/*.png`.

---

*Обновление: репозиторий проекта курсовой.*
