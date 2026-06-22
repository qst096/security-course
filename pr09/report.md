# ПР №9. Следы вредоносного ПО в Linux

## 1. Что было посажено

| Механизм | Место | Команда/файл |
|----------|-------|-------------|
| Cron | crontab пользователя | `@reboot /tmp/.hidden_malware/backdoor.sh &` <br> `*/5 * * * * /tmp/.hidden_malware/backdoor.sh &` |
| Systemd | ~/.config/systemd/user/ | system-helper.service (ExecStart=/tmp/.hidden_malware/backdoor.sh) |
| Shell profile | ~/.bashrc | `/tmp/.hidden_malware/backdoor.sh &` |
| Процесс | /tmp/.hidden_malware/ | listener.sh на порту 4444 (nc) |

## 2. Что нашли — процессы

**Команда:** `ps aux | grep '/tmp'`

**Результат:**  
posasun 2311 0.0 0.1 6940 3260 ? S 18:05 0:00 /bin/bash /tmp/.hidden_malware/backdoor.sh
posasun 2377 0.0 0.1 6940 3244 ? Ss 18:09 0:00 /bin/bash /tmp/.hidden_malware/backdoor.sh
posasun 2384 0.0 0.1 6940 3272 ? S 18:10 0:00 /bin/bash /tmp/.hidden_malware/backdoor.sh
posasun 2429 0.0 0.1 6940 3272 pts/0 S 18:12 0:00 /bin/bash /tmp/.hidden_malware/listener.sh
posasun 2464 0.0 0.1 6940 3164 ? S 18:15 0:00 /bin/bash /tmp/.hidden_malware/backdoor.sh
posasun 2558 0.0 0.1 6940 3260 ? S 18:20 0:00 /bin/bash /tmp/.hidden_malware/backdoor.sh

**Что подозрительно:**  
- Процессы запущены из `/tmp/.hidden_malware/`, что нестандартно для системных служб.
- Имена `backdoor.sh` и `listener.sh` явно указывают на вредоносную активность.
- Множество экземпляров `backdoor.sh` (из-за cron, systemd и bashrc) — признак множественного автозапуска.

## 3. Что нашли — сетевые соединения

**Команда:** `ss -tulnp | grep 4444`

**Результат:**  
tcp LISTEN 0 1 0.0.0.0:4444 0.0.0.0:* users:(("nc",pid=2430,fd=3))


**Подозрительный порт:** 4444 (классический backdoor-порт).  
**Процесс:** `nc` (netcat) с PID 2430.

**Команда:** `sudo lsof -i :4444`

**Результат:**  
nc 2430 posasun 3u IPv4 37866 0t0 TCP *:4444 (LISTEN)


**Как lsof связывает порт с процессом:**  
Показывает PID, имя процесса и открытый сокет (TCP *:4444). Это позволяет точно идентифицировать, какой процесс слушает подозрительный порт.

## 4. Что нашли — автозапуск

### Cron
**Вывод `crontab -l`:**  
@reboot /tmp/.hidden_malware/backdoor.sh &
*/5 * * * * /tmp/.hidden_malware/backdoor.sh &

**Что подозрительно:**  
- Запуск скрипта из скрытой папки `/tmp/.hidden_malware/`.
- @reboot — выполняется при каждой загрузке, что обеспечивает постоянство.
- */5 — запуск каждые 5 минут для периодической активации.

### Systemd
**Вывод `systemctl --user list-unit-files --state=enabled`:**  
system-helper.service enabled

**Содержимое unit-файла (`~/.config/systemd/user/system-helper.service`):**
[Unit]
Description=System Helper Service
After=default.target

[Service]
ExecStart=/tmp/.hidden_malware/backdoor.sh
Restart=always
RestartSec=10

[Install]
WantedBy=default.target

**Что подозрительно:**  
- Имя `system-helper.service` маскируется под системный сервис.
- ExecStart указывает на скрипт в `/tmp/.hidden_malware/`.
- Restart=always — сервис будет автоматически перезапускаться после завершения.

### ~/.bashrc
**Строка найденная в `~/.bashrc` (строка 116):**  
/tmp/.hidden_malware/backdoor.sh &

**Где находится:** в конце файла, после комментария `# system update helper`.  
**Что подозрительно:** запуск скрипта при каждом открытии терминала.

## 5. Итоговая таблица следов

| Место | Инструмент обнаружения | Что нашли |
|-------|----------------------|-----------|
| Процессы | `ps aux | grep '/tmp'` | backdoor.sh, listener.sh из /tmp/.hidden_malware/ |
| Порт 4444 | `ss -tulnp` | `nc` слушает порт 4444 |
| Файлы процесса | `sudo lsof -p 2430` | Открытый сокет IPv4, файл /usr/bin/nc.openbsd |
| Cron | `crontab -l` | @reboot и */5 записи |
| Systemd | `systemctl --user list-unit-files` | system-helper.service в enabled |
| Bashrc | `grep -n "hidden_malware" ~/.bashrc` | строка 116 с запуском backdoor.sh |

## 6. Связь с нормативкой

Какие меры ФСТЭК №17 реализует эта проверка:

| Мера | Как реализовано |
|------|-----------------|
| АНЗ.2 (обнаружение вредоносного кода) | Поиск подозрительных процессов и файлов в `/tmp/.hidden_malware/` |
| АУД.4 (аудит безопасности) | Анализ автозапуска (cron, systemd, bashrc), процессов, сетевых соединений |
| ЗИС.17 (управление сетевыми соединениями) | Обнаружение подозрительного порта 4444 и процесса `nc` |
| УПД.2 (управление правами доступа) | Проверка, что скрипты не имеют лишних привилегий (все запущены от posasun) |

## Выводы

В ходе практической работы мы:
- Создали учебный «вредонос» и прописали его в нескольких местах автозапуска (cron, systemd, bashrc).
- Провели расследование с использованием `ps`, `ss`, `lsof`, `crontab`, `systemctl`, `grep`.
- Нашли все следы: процессы из `/tmp`, слушающий порт 4444, записи в cron и systemd, добавление в bashrc.
- Убедились, что вредонос может маскироваться под системные имена (system-helper.service) и прятаться в скрытых папках.
- Зачистили все следы (остановили процессы, удалили файлы, убрали записи) и проверили, что система чиста.

**Самым неочевидным местом для нахождения вредоноса оказался пользовательский systemd-сервис** — он не виден в системных сервисах (`systemctl list-unit-files` без `--user`), и его легко пропустить.
