# pro.guap-automation
Автоматизация работы с личным кабинетом ГУАП

## Описание

Скрипт скачивает отчеты студентов из [личного кабинета ГУАП](https://pro.guap.ru).

### Авторизация
Авторизация возможна двумя способами:
- с использованием логина и пароля; для этого необходимо указать имя пользователя с ключом `-u` при вызове скрипта из командной строки; пароль необходимо будет ввести во время работы скрипта, в целях безопасности возможность указать его через командную строку отсутствует;  
пример: `python report_downloader.py -u Ivanov_IV`,  
где `Ivanov_IV` - имя пользователя (логин) портала pro.guap.ru;
- с использованием ранее созданной cookie; для этого необходимо авторизоваться в личном кабинете ГУАП в браузере, после чего с помощью инструментов разработчика в браузере найти значение куки `PHPSESSID`, скопировать его и указать в качестве аргумента командной строки при запуске скрипта с ключом `-c`;  
пример: `python report_downloader.py -c 0a1b2cde34fghij5kl6mnopqrs`,  
где `0a1b2cde34fghij5kl6mnopqrs` - значение куки `PHPSESSID`.

### Режимы работы
Скрипт может работать в двух режимах: интерактивном и режиме батч-обработки.

В интерактивном режиме скрипт выводит список всех доступных в личном кабинете семестров и предлагает пользователю выбрать интересующий его семестр. Выбор семестра осуществляется путем ввода с клавиатуры идентификатора семестра. Когда семестр выбран, скрипт выводит список всех заданий этого семестра, имеющихся в личном кабинете пользователя, и предлагает пользователю выбрать одно из них.
Выбор задания также осуществляется путем ввода идентификатора задания с клавиатуры. После выбора задания скрипт скачивает отчеты студентов, найденные в этом задании.

В режиме батч-обработки скрипт не запрашивает ввода с клавиатуры (за исключением ввода пароля при использовании авторизации по логину и паролю) и автоматически скачивает отчеты из всех заданий для выбранного семестра. Выбор семестра осуществляется с помощью ключа `-s`. Чтобы указать корректный идентификатор семестра в качестве аргумента командной строки рекомендуется сначала запустить скрипт в интерактивном режиме и ознакомиться с внутренним представлением имеющихся в личном кабинете данных.

Также можно использовать скрипт в "смешанном" режиме, указав семестр в качестве аргумента командной строки с помощью ключа `-s`, но не указывая ключ `-b`, отвечающий за включение батч-режима. В этом случае скрипт не будет запрашивать ввод идентификатора семестра, а сразу выведет список заданий и предложит выбрать интересующее. Другая комбинация - использовать ключ `-b` (батч-режим) без ключа `-s` - приведет к тому, что скрипт запросит у пользователя ввод номера семестра, после чего скачает отчеты ко всем заданиям в этом семестре.

Для того, чтобы использовать скрипт в полностью автоматическом режиме, без необходимости вводить что-либо с клавиатуры, следует использовать авторизацию с помощью cookie, ключ `-s` для указания семестра и ключ `-b` для скачивания всех отчетов выбранного семестра.

### Фильтры
Скрипт позволяет скачивать не все отчеты, а выбирать только интересующие. Поддерживаются два фильтра:
- по статусу отчета в личном кабинете (`принят`, `не принят`, `ожидает проверки`);
- по номеру группы студентов.

Фильтры работают по принципу "белого списка" (whitelist). Это значит, что будут скачаны только те отчеты, у которых статус и номер группы студента совпадают с указанными в фильтрующих списках.

По умолчанию скрипт не скачивает отчеты, имеющие статус `не принят`, т.е. фильтр по статусу отчета включает два значения: `принят` и `ожидает проверки`. Это значение по умолчанию равносильно вызову скрипта с ключом `--status accepted awaiting`. Если необходимо скачать все отчеты, в т.ч. и не принятые, можно использовать ключ `--status accepted awaiting rejected`. Следует иметь в виду, что для каждого задания в личном кабинете у одного студента может быть только один отчет в статусе `принят` и `ожидает проверки`, но отчетов в статусе `не принят` может быть произвольное количество. Чтобы скачать все отчеты, имеющие статус `не принят`, рекомендуется дополнительно указывать ключ `--keep-old`, который предотвращает автоматическое перезаписывание отчетов с одинаковым статусом, если их в личном кабинете больше одного.

По умолчанию скрипт скачивает отчеты студентов всех групп. При желании можно ограничить перечень групп, чьи отчеты будут скачаны, указав их с помощью ключа `--group`. Например, чтобы в режиме батч-обработки не скачивать отчеты студентов, которые уже завершили обучение в университете, можно явно указать перечень групп, которые в данный момент еще проходят обучение: `--group 4831 4832 4731 4736 Z7431 Z7432К`. Следует обратить внимание, что номера групп необходимо указывать строго так, как они указанны в личном кабинете. Например, заочная группа `Z7432К` содержит в своем номере английскую букву `Z` и **русскую** заглавную букву `К`. По-видимому, в таком своеобразном виде данные поступает в ЛК из АИС, но это никак не помогает простым смертным понять причины использования символов из разных раскладок в одном строковом идентификаторе (номере группы).

## Докачка отчетов
Скрипт сохраняет список загруженных отчетов в файле `downloads.log`. Это текстовый файл, его содержимое можно посмотреть любым текстовым редактором. Если в интерактивном режиме или режиме батч-обработки скрипт обнаружит отчет, который уже присутствует в списке ранее загруженных, то этот отчет повторно скачан не будет. Если необходимо скачать отчет повторно, следует или удалить файл `downloads.log` целиком, или удалить из него строки, соответствующие отчетам, которые необходимо скачать повторно.

Использование списка ранее загруженных отчетов позволяет осуществлять докачку отчетов, если по какой-либо причине работа скрипта была прервана до того, как были скачаны все необходимые отчеты. Для этого достаточно перезапустить скрипт повторно с теми же параметрами, что были указаны ранее. Скрипт сам разберется, какие отчеты уже скачаны, а какие еще нет, и докачает недостающие.

## Аргументы

Ключ `-h`, `--help` отображает краткую справку об имеющихся ключах.

Ключ `-o` позволяет задать директорию, в которую будут сохранены отчеты. По умолчанию используется текущая папка, из которой запущен скрипт.

Ключ `-v` позволяет выводить дополнительную информацию о ходе работы скрипта. 

Ключ `-d` включает вывод отладочной информации (использовать ключ `-v` в этом случае не нужно).

Ключ `-i` позволяет задать имя пользователя, от имени которого будет осуществляться просмотр личного кабинета. Данный функционал доступен пользователям с расширенными правами.

Ключ `--dry-run` позволяет запустить скрипт в демонстрационном режиме: вся информация будет выводиться в консоль (при использовании `-d`), но файлы с отчетами на жестком диске созданы не будут.

Ключ `-s` позволяет задать идентификатор семестра, чтобы не вводить его в интерактивном режиме.

Ключ `-b` включает режим батч-обработки, который позволяет запустить автоматическое скачивание всех отчетов по **всем** заданиям в выбранном семестре, без ввода идентификаторов заданий в интерактивном режиме.

Комбинация ключей `-c <токен> -s <id_семестра> -b` позволяет запустить скрипт в режиме, когда пользователю не потребуется вводить что-либо с клавиатуры (неинтерактивный режим без взаимодействия с пользователем). Это позволяет вызывать данный скрипт из других скриптов для решения более сложных задач по автоматизации.

Ключ `--status` позволяет указать фильтр по статусу отчета. Скрипт будет скачивать отчеты только с теми статусами, которые указаны в качестве аргументов этого ключа. Возможные значения: `accepted` (принят), `awaiting` (ожидает проверки), `rejected` (не принят). Несколько аргументов ключа следует разделять пробелами. Пример: `--status accepted awaiting` - позволит скачать только принятые отчеты и отчеты, ожидающие проверки (значение по умолчанию). Фильтр `--status rejected` - позволяет скачать только отчеты, статус которых в личном кабинете `не принят`.

Ключ `--group` позволяет указать список номеров групп студентов, чьи отчеты необходимо скачать. Если ключ не указан, скачиваются отчеты всех групп. Несколько аргументов ключа следует разделять пробелами. Пример: `--group 4931 4932 4933 4936` - скачать только отчеты групп 4931, 4932, 4933 и 4936, даже если в выбранных заданиях в личном кабинете есть отчеты студентов из других групп.

Ключ `--keep-old` включает защиту от перезаписывания файла с отчетом, если он уже существует в выбранной папке. Вместо этого будет создан новый файл, в конце имени которого добавится порядковый номер.

## Примеры запуска

Запустить скрипт в интерактивном режиме, указав в качестве логина на pro.guap.ru `Ivanov_IV`:
```
python report_downloader.py -u Ivanov_IV
```

Запустить скрипт в режиме батч-обработки, чтобы он скачал отчеты ко всем заданиям семестра `16` (2020/2021 осень) в папку `осень_2020`. Выводить в консоль информацию о ходе работы скрипта:
```
python report_downloader.py -c 0a1b2cde34fghij5kl6mnopqrs -s 16 -b -o "осень_2020" -v
```

Запустить скрипт в интерактивном режиме авторизовавшись как пользователь `Ivanov_IV`, и перейти к просмотру отчетов от имени польвателя `Petrov_PP` (у пользователя `Ivanov_IV` должны быть соответствующие права доступа к личным кабинетам других пользователей):

```
python report_downloader.py -u Ivanov_IV -i Petrov_PP
```