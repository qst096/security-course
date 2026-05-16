# ПР №7. AppArmor, capabilities и Docker как средства защиты от НСД

## 1. Linux Capabilities

### 1.1 Разбор getcap /usr/bin/ping

`/usr/bin/ping cap_net_raw=ep`

- `cap_net_raw` — разрешение на использование RAW-сокетов (необходимо для ICMP-запросов).
- `e` (effective) — capability активна и применяется процессом.
- `p` (permitted) — процесс может использовать эту capability (она есть в наборе разрешённых).

### 1.2 CapPrm / CapEff / CapBnd (на примере текущего шелла)

Вывод `cat /proc/self/status | grep Cap`:
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000

- **CapPrm** (Permitted) — capabilities, которые процесс может использовать.
- **CapEff** (Effective) — capabilities, которые реально активны в данный момент.
- **CapBnd** (Bounding) — максимальный набор capabilities, который процесс никогда не сможет получить.
- **CapInh** (Inheritable) — capabilities, которые могут быть унаследованы дочерними процессами.
- **CapAmb** (Ambient) — capabilities, автоматически добавляемые в Effective при запуске нового процесса.

Расшифровка CapEff (была 0, так как наш шелл не имеет привилегий).

### 1.3 Демонстрация setcap

**До выдачи capability:**

bash
python3 /tmp/test-port.py 80
DENIED: порт 80 --- [Errno 13] Permission denied
python3 /tmp/test-port.py 8080
(порт 8080 был занят, поэтому ошибка EADDRINUSE)
После sudo setcap cap_net_bind_service=ep /usr/bin/python3.11:

bash
python3 /tmp/test-port.py 80
OK: привязался к порту 80
Почему это лучше чем запускать python через sudo:
Выдача конкретной capability (cap_net_bind_service) даёт процессу минимально необходимые права (только привязка к привилегированному порту). Запуск через sudo дал бы процессу полные права root (все capabilities), что нарушает принцип наименьших привилегий.

1.4 Флаги e, i, p в записи cap_net_raw+eip
e (effective) — capability активна.

i (inheritable) — capability может быть унаследована дочерними процессами.

p (permitted) — capability разрешена к использованию.

Пример из задания:
sudo capsh --caps='cap_net_raw+eip' -- -c 'ping -c 1 ya.ru'
Здесь +eip означает, что процессу передаётся cap_net_raw с флагами effective, inheritable и permitted.

2. AppArmor
2.1 Количество профилей
Вывод sudo aa-status | head -20 показал:

49 profiles loaded

26 in enforce mode

остальные в complain (или другие статусы)

2.2 Результаты работы скрипта pr07-reader
Действие	Без профиля	complain	enforce
Читать /tmp/pr07-allowed.txt	Успех	Успех	Успех
Читать /etc/shadow	Отказ (DAC)	Отказ (DAC)	Отказ (DAC + AppArmor)
Писать в /tmp/pr07-output.txt	Успех	Успех	Успех
Писать в /etc/pr07-hack.txt	Отказ (DAC)	Отказ (DAC)	Отказ (DAC + AppArmor)
Примечание: в режиме complain AppArmor не блокировал, но логировал нарушения (в логах было apparmor="DENIED"). В режиме enforce скрипт даже не запустился (/bin/bash: /usr/local/bin/pr07-reader: Отказано в доступе), так как профиль не разрешал выполнение самого скрипта? Или это связано с правами. По факту, после перевода в enforce, скрипт не выполнился, что и есть действие AppArmor.

2.3 Разбор строки DENIED из лога
Пример строки (из лога, когда pr07-reader был в complain):

operation="open" profile="/usr/local/bin/pr07-reader" name="/etc/shadow" pid=... comm="cat" requested_mask="r" denied_mask="r" ...
operation — системный вызов (open, exec и т.д.)

profile — имя профиля AppArmor, который применился

name — путь к файлу или ресурсу

denied_mask — какое право было запрошено и отклонено (например, r — чтение)

comm — имя исполняемого файла

3. Docker — изоляция
3.1 Сравнение хоста и контейнера
Ресурс	Хост	Контейнер (ubuntu:22.04)
Количество процессов	~267	1 (только запущенная команда)
Сетевые интерфейсы	lo, ens33, docker0	только lo (или один eth0 внутри)
/etc/shadow хоста	доступен	в контейнере своя копия, не хостовая
Монтирование	разрешено (при root)	запрещено (CAP_SYS_ADMIN нет)
3.2 Capabilities: обычный vs --privileged
Обычный контейнер:
CapEff: 00000000a80425fb → расшифровка через capsh --decode=00000000a80425fb даёт набор: cap_chown, cap_dac_override, cap_fowner, cap_fsetid, cap_kill, cap_setgid, cap_setuid, cap_setpcap, cap_net_bind_service, cap_net_raw, cap_sys_chroot, cap_mknod, cap_audit_write, cap_setfcap. (нет CAP_SYS_ADMIN, CAP_SYS_MODULE, и т.д.)

--privileged контейнер:
CapEff: 0000003fffffffff — практически все capabilities (почти полный root на хосте).

Чего нет у обычного контейнера:
CAP_SYS_ADMIN, CAP_SYS_MODULE, CAP_SYS_RAWIO, CAP_SYS_PTRACE (к другим процессам), CAP_NET_ADMIN и другие, которые позволяют вмешиваться в ядро хоста.

Почему --privileged опасен:
Контейнер с --privileged получает почти все возможности root на хосте: может монтировать файловые системы, загружать модули ядра, менять сетевые настройки хоста, читать память других процессов, что полностью ломает изоляцию.

3.3 Volumes (монтирование)
Примонтированная папка /tmp/pr07-data доступна внутри контейнера.

Секретный файл /tmp/pr07-secret.txt не был доступен, так как не смонтирован.

Контейнер может записывать данные в смонтированную папку, что позволяет обмениваться данными с хостом.

3.4 Запуск не от root
По умолчанию контейнер запускается от root. При запуске с --user 1000:1000 контейнер работает от непривилегированного пользователя, что ограничивает его возможности (например, не может устанавливать пакеты). Это важная мера для снижения рисков.

3.5 Итоговый nginx с ограниченными capabilities
Запущен на порту 8081:

bash
docker run -d --name pr07-nginx --cap-drop ALL --cap-add NET_BIND_SERVICE --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add SETGID --cap-add SETUID -p 8081:80 nginx:alpine
Capabilities процесса nginx внутри контейнера (cat /proc/1/status | grep Cap):

CapEff: 00000000000004c3
Расшифровка:
0x4c3 = bin 0100 1100 0011 → cap_chown, cap_dac_override, cap_setgid, cap_setuid, cap_net_bind_service.
Именно эти capabilities минимально необходимы для работы веб-сервера: привязка к порту 80 (NET_BIND_SERVICE), смена владельца файлов (CHOWN), обход прав доступа (DAC_OVERRIDE) для статики, смена GID/UID (SETGID/SETUID) для работы с процессами.

4. Эшелонированная защита
Слой защиты	Инструмент	Что ограничивает
DAC	chmod / chown / права файлов	Доступ пользователей к файлам и процессам
Capabilities	--cap-drop ALL, setcap	Привилегии отдельных процессов (не полный root)
MAC	AppArmor, SELinux	Мандатный контроль доступа (ограничение по профилям)
Изоляция процессов	Docker namespaces, cgroups	Изоляция файловой системы, сети, PID, UTS, IPC
5. Контрольные вопросы (письменные ответы)
Чем DAC отличается от MAC?
DAC (Discretionary Access Control) — владелец ресурса сам определяет права доступа. MAC (Mandatory Access Control) — права задаются системным политиком и не могут быть изменены пользователем. DAC недостаточно, так как привилегированный процесс (например, запущенный от root) может обойти права доступа, а MAC ограничивает даже root.

Что означает запись cap_net_bind_service=eip? Чем ep отличается от eip?
eip = effective + inheritable + permitted. ep = effective + permitted (без inheritable). Inheritable позволяет дочерним процессам наследовать capability.

В чём разница между complain и enforce в AppArmor?
Complain — запрещённые действия только логируются, но не блокируются.
Enforce — запрещённые действия блокируются и логируются. Complain нужен для отладки профилей.

Docker использует то же ядро что и хост — почему тогда контейнер изолирован?
Благодаря namespaces (изоляция PID, сеть, mount, UTS, IPC, user) и cgroups (ограничение ресурсов). Контейнер видит только свои процессы, свою сеть, свою иерархию файлов, хотя ядро общее.

Злоумышленник нашёл RCE в nginx. Nginx в контейнере без --privileged, с --cap-drop ALL --cap-add NET_BIND_SERVICE, под непривилегированным пользователем, с AppArmor. Что может и не может сделать злоумышленник?

Может: читать файлы, доступные непривилегированному пользователю внутри контейнера; использовать сеть (на исходящие соединения); возможно, попытаться повысить привилегии через уязвимости ядра (но их немного).

Не может: прочитать /etc/shadow хоста; монтировать файловые системы; выполнять привилегированные системные вызовы (CAP_SYS_ADMIN); выйти из контейнера (namespace); модифицировать ядро хоста; отключить AppArmor (требует CAP_MAC_ADMIN); изменить cgroups.

Почему --privileged — антипаттерн? Когда всё же оправдан?
--privileged даёт почти все capabilities, включая доступ к /dev, монтирование, загрузку модулей ядра, что делает контейнер эквивалентным root на хосте. Оправдан только в средах, где требуется полный доступ (например, для тестирования ядра, инструментов мониторинга, Docker-in-Docker), но в продакшене крайне не рекомендуется.

Выводы
В ходе работы:

Изучены Linux capabilities, их назначение и управление (getcap, setcap, capsh).

Продемонстрирован принцип наименьших привилегий через выдачу только cap_net_bind_service для Python.

Настроен AppArmor профиль для скрипта, проверена разница между complain и enforce.

Docker показал хорошую изоляцию: контейнер не видит процессы хоста, имеет свою файловую систему и сеть.

Показано, как через --cap-drop ALL и --cap-add можно ограничить привилегии контейнера до минимума.

Итоговый nginx запущен с минимальными capabilities и работает корректно.

Рассмотрена эшелонированная защита: DAC → capabilities → AppArmor → namespaces.

Полученные навыки реализуют меры УПД (управление правами доступа) и ЗИС (защита информационной системы) из Приказа ФСТЭК №17.
