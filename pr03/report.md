# ПР №3. Права доступа Linux и управление пользователями

## 1. Пользователи и группы

Созданные пользователи и их роли:

| Пользователь | Группа       | Роль                |
|--------------|--------------|---------------------|
| alice        | developers   | Администратор проекта |
| bob          | developers   | Разработчик         |
| carol        | auditors     | Аудитор             |

Поля /etc/passwd (разбор строки alice):

Вывод `getent passwd alice`:
alice:x:1001:1001::/home/alice:/bin/bash

text

- `alice` — имя пользователя
- `x` — пароль хранится в /etc/shadow
- `1001` — UID
- `1001` — GID (основная группа)
- (пусто) — комментарий
- `/home/alice` — домашняя директория
- `/bin/bash` — командная оболочка

Содержимое /etc/shadow (вывод `sudo grep -E 'alice|bob|carol' /etc/shadow`):
alice:
6
6... (хэш скрыт)
bob:
6
6...
carol:
6
6...

text
В этом файле хранятся хэши паролей и параметры срока действия. Обычные пользователи не могут его читать, чтобы злоумышленник не получил хэши.

## 2. Права доступа chmod/chown

Структура каталогов после создания:
/srv/project/
├── code (владелец alice:developers)
├── reports
└── logs

text

Вывод `ls -la /srv/project/`:
итого 20
drwxr-xr-x 5 root root 4096 мая 5 17:21 .
drwxr-xr-x 3 root root 4096 мая 5 17:21 ..
drwxr-x--- 2 alice developers 4096 мая 5 17:21 code
drwxr-xr-x 2 root root 4096 мая 5 17:21 logs
drwxr-xr-x 2 root root 4096 мая 5 17:21 reports

text

Права на `code`: `chmod 750` → `drwxr-x---`.

- bob (в группе developers) при попытке создать файл получил отказ: `touch: невозможно выполнить touch для '/srv/project/code/test.py': Отказано в доступе`.  
  Причина: у группы нет права записи (только чтение и выполнение).
- carol (не в группе developers) не может войти в папку: `ls: невозможно открыть каталог '/srv/project/code': Отказано в доступе`.

После `sudo chmod 770 /srv/project/code` (права `drwxrwx---`) bob смог создать файл `hello.py`:
итого 8
drwxrwx--- 2 alice developers 4096 мая 5 17:23 .
drwxr-xr-x 5 root root 4096 мая 5 17:21 ..
-rw-r--r-- 1 bob bob 0 мая 5 17:23 hello.py

text

Файл `q1.txt` создан в `/srv/project/reports/` со следующими командами:
touch /srv/project/reports/q1.txt
chmod 640 /srv/project/reports/q1.txt
chown alice:auditors /srv/project/reports/q1.txt

text

Итоговые права: `-rw-r-----` (числовые 640).  
Владелец alice (чтение+запись), группа auditors (чтение), остальные — ничего.  
Carol, входящая в группу auditors, смогла прочитать файл (команда `cat` выполнена без ошибок, файл пуст).

## 3. ACL

Задача: дать carol доступ на чтение к `code` без изменения группы.

Исходные ACL:
file: srv/project/code
owner: alice
group: developers
user::rwx
group::rwx
other::---

text

Команда добавления ACL: `setfacl -m u:carol:r-x /srv/project/code`

Новые ACL:
file: srv/project/code
owner: alice
group: developers
user::rwx
user:carol:r-x
group::rwx
mask::rwx
other::---

text

В выводе `ls -la /srv/project/ | grep code` появился `+`: `drwxrwx---+ 2 alice developers ...`

Проверки:
- carol может видеть файлы: `su - carol -c 'ls /srv/project/code'` → `hello.py`
- carol не может создать файл: `touch: невозможно выполнить touch ... Отказано в доступе`

После удаления ACL (`setfacl -x u:carol /srv/project/code`) доступ carol снова закрыт.

ACL удобнее стандартной модели, так как позволяет точечно давать права конкретному пользователю без изменения группы владельца или добавления пользователя в группу.

## 4. sudo-политики

В `/etc/sudoers` добавлены строки (проверка `visudo -c` → `parsed OK`):
alice ALL=(ALL:ALL) NOPASSWD:ALL
bob ALL=(ALL) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get
carol ALL=(ALL) NOPASSWD: /usr/bin/journalctl, /bin/cat /var/log/*

text

Вывод `sudo -l -U` для каждого пользователя (проверено через `su - пользователь -c 'sudo -l'`):

**alice:**
User alice may run the following commands on EgorEblan2006:
(ALL : ALL) NOPASSWD: ALL

text

**bob:**
User bob may run the following commands on EgorEblan2006:
(ALL) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get

text

**carol:**
User carol may run the following commands on EgorEblan2006:
(ALL) NOPASSWD: /usr/bin/journalctl, /bin/cat /var/log/*

text

Проверка ограничений для bob: попытка выполнить `sudo journalctl` требует ввода пароля (NOPASSWD не указан) и при использовании `su - bob -c 'sudo journalctl -n 1'` выдаёт сообщение о необходимости терминала, что подтверждает отсутствие права.

Принцип наименьших привилегий реализован: alice имеет полный доступ, bob — только к apt, carol — только к просмотру логов.

## 5. PAM

Содержимое `/etc/pam.d/sudo` (основные строки):
#%PAM-1.0
session required pam_limits.so
@include common-auth
@include common-account
@include common-session-noninteractive

text

Модуль `pam_unix.so` подключается через `@include common-auth`.  
В файле `/etc/pam.d/common-password` строка с `pam_unix.so`:
password [success=1 default=ignore] pam_unix.so obscure yescrypt

text
Ключевое слово `obscure` включает проверки качества пароля (минимальная длина, не должен совпадать с предыдущим и т.д.).  
Минимальная длина пароля по умолчанию в Debian 12 — 8 символов (задаётся в `/etc/login.defs`). Чтобы увеличить до 12, нужно добавить параметр `minlen=12` в строку модуля `pam_unix.so` или подключить модуль `pam_pwquality.so` с параметром `minlen=12`.

## 6. Выводы

В ходе работы:
- Созданы пользователи и группы в соответствии с ролевой моделью.
- Настроены стандартные права доступа (chmod, chown) к каталогам и файлам, проверена работа принципа «наименьших привилегий».
- Использованы ACL для предоставления индивидуального доступа без изменения прав владельца или группы.
- Настроены политики sudo с ограничением выполняемых команд.
- Изучены конфигурационные файлы PAM и механизм аутентификации.

Полученные навыки реализуют требования группы мер УПД (Управление правами доступа) Приказа ФСТЭК №1

## 7. Контрольные вопросы

1. **Что означает запись chmod 640 и кто при этом может читать файл?**  
   `chmod 640` означает права `-rw-r-----`. Владелец может читать и писать, группа — только читать, остальные не имеют доступа. Читать файл могут владелец и пользователи, входящие в группу-владельца.

2. **Чем setuid-бит на исполняемом файле отличается от sudo? Приведите пример.**  
   `setuid` (например, `chmod u+s /usr/bin/passwd`) позволяет запускать файл от имени **владельца** файла (обычно root), не требуя ввода пароля. `sudo` требует авторизации и позволяет выполнять отдельные команды от имени root (или другого пользователя) на основе политик. Пример: `passwd` использует setuid для изменения пароля, а `sudo apt update` использует sudo для временного получения привилегий.

3. **Почему хэши паролей хранятся в /etc/shadow, а не в /etc/passwd?**  
   `/etc/passwd` доступен для чтения всем пользователям. Хранение хэшей паролей там позволило бы злоумышленнику копировать хэши и подбирать пароли офлайн. `/etc/shadow` доступен только root, что повышает безопасность.

4. **Что произойдёт если дать пользователю bob запись sudo bash? Почему это опасно?**  
   Запись `bob ALL=(ALL) NOPASSWD: /bin/bash` позволит bob запустить `sudo bash` и получить полноценную root-оболочку, после чего он сможет выполнять любые команды, игнорируя ограничения. Это опасно, так как нарушает принцип наименьших привилегий.

5. **Назовите разницу между командами su и sudo с точки зрения безопасности.**  
   `su` требует пароль целевого пользователя (обычно root) и переключает на него полностью, часто с наследованием окружения. `sudo` запрашивает пароль текущего пользователя и позволяет выполнить только конкретную команду с правами root, при этом ведётся журнал. `sudo` безопаснее, так как не требует раздачи пароля root и даёт тонкую настройку прав.

6. **Как запретить конкретному пользователю использовать sudo, не удаляя его из группы sudo?**  
   В файле `/etc/sudoers` добавить строку `имя_пользователя ALL=(ALL) !ALL` или использовать `deny` после указания прав. Например: `bob ALL=(ALL) !ALL`. Это явно запрещает все команды, даже если пользователь в группе sudo.
