# pro.guap-automation
Автоматизация работы с личным кабинетом ГУАП

## Описание

Скрипт скачивает отчеты студентов из [личного кабинета ГУАП](https://pro.guap.ru).

Авторизация возможна двумя способами:
- с использованием логина и пароля; для этого необходимо указать имя пользователя с ключом `-u` при вызове скрипта из командной строки;  
пример: `python report_downloader.py -u Ivanov_IV`,  
где `Ivanov_IV` - имя пользователя (логин) портала pro.guap.ru;
- с использованием ранее созданной cookie; для этого необходимо авторизоваться в личном кабинете ГУАП в браузере, после чего с помощью инструментов разработчика в браузере найти значение куки `PHPSESSID`, скопировать его и указать в качестве аргумента командной строки при запуске скрипта с ключом `-c`;  

пример: `python report_downloader.py -c 0a1b2cde34fghij5kl6mnopqrs`,  
где `0a1b2cde34fghij5kl6mnopqrs` - значение куки `PHPSESSID`.

## Аргументы

Ключ `-o` позволяет задать директорию, в которую будут сохранены отчеты. По умолчанию используется текущая папка, из которой запущен скрипт.

Ключ `-v` позволяет выводить дополнительную информацию о ходе работы скрипта. 

Ключ `-d` включает вывод отладочной информации (использовать ключ `-v` в этом случае не нужно).

Ключ `-i` позволяет задать имя пользователя, от имени которого будет осуществляться просмотр личного кабинета. Данный функционал доступен пользователям с расширенными правами. **ВНИМАНИЕ!!!** _Работоспособность не проверялась из-за отсутствия соответствующих прав доступа к личному кабинету_

Ключ `--dry-run` позволяет запустить скрипт в демонстрационном режиме: вся информация будет выводиться в консоль (при использовании `-d`), но файлы с отчетами на жестком диске созданы не будут.

Ключ `-s` позволяет задать идентификатор семестра, чтобы не вводить его в интерактивном режиме.

Ключ `-b` позволяет запустить автоматическое скачивание всех отчетов по **всем** заданиям в выбранном семестре, без ввода идентификаторов заданий в интерактивном режиме.

Комбинация ключей `-c <токен> -s <id_семестра> -b` позволяет запустить скрипт в режиме, когда пользователю не потребуется вводить что-либо с клавиатуры (неинтерактивный режим без взаимодействия с пользователем). Это позволяет вызывать данный скрипт из других скриптов для решения более сложных задач.

## Примеры запуска

Запустить скрипт в интерактивном режиме, указав в качестве логина на pro.guap.ru `Ivanov_IV`:
```
python report_downloader.py -u Ivanov_IV
```

Запустить скрипт в фоновом режиме, чтобы он скачал отчеты ко всем заданиям семестра `16` (2020/2021 осень) в папку `осень_2020`. Выводить в консоль информацию о ходе работы скрипта
```
python report_downloader.py -c 0a1b2cde34fghij5kl6mnopqrs -s 16 -b -o "осень_2020" -v
```

Запустить скрипт в интерактивном режиме авторизовавшись как пользователь `Ivanov_IV`, и перейти к просмотру отчетов польвателя `Petrov_PP` (у пользователя `Ivanov_IV` должны быть соответствующие права доступа к личному кабинету):

```
python report_downloader.py -u Ivanov_IV -i Petrov_PP
```
**NB!** Работоспособность данного функционала не гарантирована в связи с отсутствием возможности протестировать его!