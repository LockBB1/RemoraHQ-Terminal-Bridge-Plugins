# RemoraHQ - Terminal Bridge

MeshCentral plugin providing the server-side validator + correlation issuer
for RemoraHQ terminal sessions. Fifth member of the `RemoraHQ - *` plugin
family.

## Identity

| Field | Value |
|-------|-------|
| Display name | `RemoraHQ - Terminal Bridge` |
| Short name (Mesh shortName) | `remoraTerminalBridge` |
| Entry file | `remoraTerminalBridge.js` |
| Source repo folder | `RemoraHQ-Terminal-Bridge-Plugins` |
| Deploy folder under Mesh | `meshcentral/plugins/remoraTerminalBridge` |

## Terminal contract (Bridge 0.14.3)

The `open` action accepts `nodeId`, `shell` (`cmd`, `powershell`, `bash`,
`zsh`) and the optional `context: "user"`. It returns a session identifier,
relay URL, native User protocol (8 or 9), and agent tunnel details. The plugin
does not open the relay socket itself. The matching SPA retains its User connect
step-up check and sends only User options; this is not a route-wide MFA wrapper.

Operator and SYSTEM modes are disabled, including requests using old grants or
TOTP. `openAdmin` returns `terminal_admin_unavailable` without verifying a
password or issuing a relay cookie. Admin remains unavailable until the specialist's
Windows identity and SID can be verified safely. The intended Admin contract does
not require UAC elevation. Unsupported legacy inputs are
rejected instead of falling back to User.

This applies only to this plugin and matching SPA. Native MeshCentral relay and
agent behavior are separate and unchanged; this does not close that route.
Deployments need matching plugin and SPA versions. The `.setup` snapshot is not
updated by edits to this checkout.

## Remote Install 0.14.3

Цели — Windows x64 с Windows PowerShell 5.1 и WinRM. Сервер — Windows
(сохранённый DPAPI LocalMachine/Negotiate путь) либо Debian (Ruby WinRM,
Kerberos/GSSAPI). Debian требует полный DNS hostname, SPN `HTTP/hostname`,
доступ к KDC/DNS и учётную запись `user@REALM`; IP, NTLM fallback и локальные
учётные записи для Debian не поддерживаются. LDAP-вход в MeshCentral сам по
себе не подтверждает Kerberos/WinRM. WinRM HTTP/5985 использует шифрование
сообщений GSSAPI, пароль в WinRM-клиент не передаётся.

Отдельная диагностика передаёт новый установщик выбранной группы и сообщает
результаты проверки его SHA-256 и Authenticode, наличие signer и подтверждение
очистки. Она не запускает установку или удаление и не проверяет ранее переданный
файл. Потеря связи или неподтверждённая очистка означает неизвестный результат.

Для **каждого** Install/Reinstall/Remove сервер проверяет authenticated user,
`canRemoteInstall` и `MESHRIGHT_EDITMESH` на выбранную существующую Machine
Group типа 2. По решению владельца эта привилегия позволяет указать любой
доступный push account Windows-ПК, включая агент старого сервера; выбранная
группа не является доказательством принадлежности ПК. Выдавайте её только
операторам, которым разрешён такой охват. Push Account остаётся super-admin-only.
Действия не требуют TOTP и не удаляют записи ни с текущего, ни со старого сервера.

| `remoteInstall.run.mode` | Поведение |
| --- | --- |
| `install` (также default для прежнего API) | Проверка дубликата по DB fail-closed и независимая проверка служб на самом ПК; найденный агент блокирует установку. |
| `reinstall` | Свежий installer текущего сервера выполняет `-fulluninstall` с явным `--meshServiceName`; после подтверждения удаления службы, Diagnostic-службы и старых EXE/MSH он устанавливает агент выбранной группы. |
| `remove` | Тот же свежий installer удаляет найденную установку без последующей установки. Установленный на ПК EXE не запускается. |

`-uninstall` и `-fulluninstall` не взаимозаменяемы: первый удаляет службу,
второй также очищает установленный агент. Используется второй; его exit 0
не заменяет проверку отсутствия служб. Реальный эффект зависит от сборки
MeshAgent и должен быть принят на тестовом ПК. При timeout/ошибке удаления
новая установка не запускается.

Переданный installer сверяется на ПК с SHA-256 серверного файла для всех
трёх действий. Перед запуском он копируется в отдельную папку операции внутри
защищённого SYSTEM/Administrators каталога и повторно сверяется с SHA-256;
рядом с ним нет policy/DB прежней установки. Доверенный Windows корень и
совпадение сертификатов старого и нового агента не требуются: исполняется
только свежий installer сервера, а не установленный EXE.

Перед удалением проверяются основная и найденная Diagnostic-служба: локальные
канонические пути без reparse points, shell expansion и неоднозначного разбора
ImagePath, безопасные имена файлов и одна выделенная папка. Системные каталоги
и корни диска/Program Files/ProgramData запрещены. Установка распознаётся по
`.msh` с MeshID/ServerID либо штатному имени службы и имени `MeshAgent.exe`;
в последнем случае policy может быть embedded. Кастомный EXE без `.msh`,
Diagnostic в другой папке, отсутствующие файлы и неоднозначные службы требуют
ручной диагностики. Никакой перебор удаления всех установок или исполнение
произвольного registry uninstall command не выполняется.

В upstream [agent-installer.js](https://github.com/Ylianst/MeshAgent/blob/0e6b4f7fea6c88ad1978206550d202a7f33741c5/modules/agent-installer.js)
`fullUninstall` выбирает службу через `meshServiceName`, а
[service-manager.js](https://github.com/Ylianst/MeshAgent/blob/0e6b4f7fea6c88ad1978206550d202a7f33741c5/modules/service-manager.js)
берёт удаляемый EXE из её ImagePath; файл прежнего агента не исполняется.
Upstream cleanup может удалять файлы с тем же базовым именем и пустые папки,
поэтому preflight проверяет и связанные файлы. После завершения uninstaller скрипт ждёт 12 s
(известный upstream detached self-delete использует 10 s), затем до 20 s
проверяет отсутствие старых EXE/MSH и служб. Сохранившиеся файлы блокируют
fresh install; самостоятельно они не удаляются. Эти задержки и соответствие
конкретной сборке свежего installer требуют server smoke. Upstream устанавливает
`MeshAgent` независимо от имени переданной копии, а embedded MSH читает из EXE;
это подтверждение по исходникам, запуск реального бинарника из защищённой папки
и его подключение должны быть проверены владельцем. При неизвестном исходе
защищённая копия installer и target lock сохраняются для ручной проверки.
При отсутствии службы Reinstall/Remove возвращают
`agent_not_found`; автоматического перехода к Install нет. Кастомные установки,
которые невозможно распознать по службе или `.msh`, также требуют отдельной
проверки перед использованием. Для Install не поддерживаются произвольные
branding/serviceName настройки; устанавливается штатный агент текущего сервера.

Run принимает `host`, `groupId`, необязательные `installFlags` (0–3), `mode`,
`operationId` (32 lowercase hex). Для destructive mode требуется
`confirmedHost`, точно равный `host`. SPA требует живой Check с
`lifecycleVersion: 1` перед Reinstall/Remove: старый plugin мог бы проигнорировать
неизвестный mode. Deploy matching SPA и Bridge вместе; старые setup snapshots
сами не обновляются от изменения этого checkout.

Один worker ограничен 180 s, подготовка installer — 30 s, новый SPA RPC run —
240 s. Остальные RPC сохраняют обычный timeout. Результат `installer_completed`
означает завершение installer, **не подтверждённое подключение агента**;
проверьте группу отдельно. `removed` подтверждает отсутствие служб и старых EXE/MSH, без
обещания удаления каждой оставшейся папки/registry entry. Ошибка соединения,
timeout, потерянный маркер и сбой после начала destructive действия до подтверждения результата — неизвестный
исход. Ни UI, ни helper не повторяют его автоматически. Локальный guard
закреплённой WinRM запрещает повторную Kerberos инициализацию после 401 и
повтор command при WSMan shell reset. Постоянный receipt intent на цели служит
дополнительной защитой от повторного исполнения.

Подтверждённый результат lifecycle сохраняется при последующем сбое удаления
временных файлов или закрытия WinRM-сессии. Guard также сохраняет полный ответ
`Base#run`, если внутренний `cleanup_command` WinRM выбрасывает исключение после
чтения ответа; в этом случае очистка отмечается `unknown`. Успех по-прежнему
требует возвращённого ответа с нулевым exit code и допустимым lifecycle-маркером:
ошибка чтения или отсутствующий exit code не превращаются в успех.
Дополнительное optional поле
`cleanup: confirmed | unknown` в run/status и аудите сообщает об уборке отдельно
от `outcome`; SPA показывает предупреждение при `unknown`. Статус `confirmed`
требует подтверждения очистки защищённой копии и target lock, переданного EXE,
закрытия сессии и серверных временных файлов. При ошибке до подтверждённого
маркера исход остаётся `unknown`; завершённый процесс сам по себе не заменяет
подтверждение lifecycle. Поле отсутствует в старых сохранённых записях.

`remoteInstall.status {host, groupId}` — read-only статус последнего intent:
`running`, `completed`, `failed`, `unknown`, `outcome`, `mode`, `operationId`, optional `cleanup`.
После потери связи используйте Refresh outcome; неизвестный результат
блокирует новый run. Локальные `remora-ri-operations/` записи/lock сохраняются
в datapath до разрешения; после перезапуска незавершённый `running` читается
как `unknown`. На ПК защищённый SYSTEM/Administrators каталог
`%ProgramData%\RemoraHQ-RemoteInstall` содержит общий atomic lock и receipts.
Это также блокирует конкурирующие aliases/серверы. Не очищайте active lock по
таймеру. Для ручного восстановления сначала остановите новые push, подтвердите
отсутствие выполняющегося installer/uninstaller и фактическое состояние ПК,
сверьте аудит/operationId, затем адресно разрешите соответствующие server record
и `.lock` и target `active`. Receipts оставляйте до окончания согласованного
периода хранения intent; автоматической ротации/очистки здесь нет.

Rate limits: 20 run/минуту на actor, не более четырёх active run на процесс,
отдельный бюджет reachability/status;
счётчики локальны процессу. Lock/receipt на цели остаётся последней границей
конкуренции между серверами. Аудит содержит действие, actor, target/group,
operationId и безопасный outcome, без raw WinRM/DPAPI/Kerberos ошибок.

### Debian: локальный зашифрованный Push Account

Пароль хранится в `datapath/remora-remoteinstall.json` (`0600`, владелец — UID
процесса) как AES-256-GCM с новым 12-byte IV и authenticated username. Ключ —
**32 сырых случайных байта**, отдельный файл вне datapath, Git, БД и образа.
`REMORA_RI_KEY_FILE` содержит только абсолютный путь к нему. Код отказывает
при неправильной длине, symlink, чужом владельце, доступе group/other к файлу
или writable group/other родительском каталоге. Администратор хоста/Docker
или захваченный процесс с доступом к ключу и ciphertext может извлечь пароль.
Это локальное at-rest шифрование, не защита от администратора узла.

Пример подготовки **на сервере владельцем**, вне репозитория (не выполняется
plugin автоматически; UID должен соответствовать runtime, пример для root):

```sh
install -d -m 0700 /srv/remorahq-secrets
umask 077
openssl rand -out /srv/remorahq-secrets/push.key 32
chmod 0400 /srv/remorahq-secrets/push.key
```

Выдайте файл только MeshCentral контейнеру read-only через Compose secret
`/run/secrets/remora-ri-key` и задайте
`REMORA_RI_KEY_FILE=/run/secrets/remora-ri-key`. Подмонтируйте проверенный
`/etc/krb5.conf` read-only; DNS/realm/SPN и время настраивает администратор.
Compose file-backed secrets могут сохранять host UID/mode: проверьте их внутри
контейнера без вывода содержимого; `uid/mode` YAML сам по себе не доказывает права.
Секреты не кладите в environment, command line, Compose YAML или image layer.
Образ и pinned Ruby dependencies готовит root `docker/meshcentral/`; установите
также полный каталог plugin, включая `remote-install/`, затем перезапустите
MeshCentral. Суперадминистратор сохраняет учётную запись через Push Account,
проверяет decrypt-only, затем WinRM на согласованном тестовом ПК. Пароль после
сохранения обратно не возвращается.

Для каждого job helper выполняет новый `kinit -l 10m -F -P`, пароль поступает
через stdin, ccache живёт в отдельном `0700` каталоге. Билеты не разделяются
между job и не требуют фонового renewal: следующий запуск получает новый TGT,
в том числе после reboot. Parent очищает каталог при завершении/timeout и
убивает process group, включая kinit. При аварийном завершении самого Node/хоста
cleanup не гарантируется; используйте private/tmpfs `/tmp`, tickets не включайте
в backups. Debug SOAP и сырые ошибки отключены, stdout допускает только markers.
Pinned WinRM 2.4.1 проверяется helper; локальный guard дополнительно требует
успешный статус GSSAPI и conf_state=1 для wrap/unwrap. Переход версии требует
повторной проверки этого guard и реального Kerberos smoke.

Для смены **пароля** обновите AD credential и сразу сохраните новое значение
через super-admin UI, затем decrypt/bind test. Для смены **ключа** остановите
новые push и дождитесь известного результата активных job, подготовьте новый
отдельный key/secret mount, перезапустите runtime и заново сохраните пароль
через UI. Автоматического decrypt/rekey старого файла нет. Старые backups
оставляйте со старым ключом в отдельном защищённом хранилище. Для восстановления
нужны соответствующие друг другу ciphertext + ключ, корректные UID/mode и
krb5/DNS/time конфигурация; после восстановления повторите decrypt/bind test.
Без ключа пароль не восстанавливается — super-admin вводит новую credential.
Windows DPAPI blob на Debian не мигрирует: сохраните account заново; Windows
путь продолжает использовать прежний LocalMachine blob/entropy.

### Проверка и источники

`npm test` исполняет dispatcher/credential guards/cleanup на синтетических
filesystem/process/DB fixtures, включая Linux timeout. `npm run test:kerberos`
требует Ruby и installed pinned WinRM; проверяет запуск helper с конфликтующей
версией logger в изолированном bundle, обработку диагностики и cleanup,
Ruby dispatch GSSAPI guard
с синтетической FFI и реальные методы pinned gem на 401/WSMan fault без HTTP,
а также сохранение полного ответа и исходной ошибки чтения при сбое внутреннего
command cleanup без повторного запуска команды.
`powershell.exe -NoProfile -NonInteractive -File test/diagnostic.ps1` проверяет
независимую классификацию SHA-256 и подписи с синтетическими результатами.
`powershell.exe -NoProfile -NonInteractive -File test/lifecycle.ps1` выполняет
копию target script в temporary directory: identity/ACL/signatures/services и
process запуск мокируются, реальные службы/установщики не затрагиваются.
Это не проверки реального DPAPI, Linux filesystem UID/ABI, Kerberos, WinRM,
Authenticode, служб или установки. Перед rollout владелец должен проверить
сборку Debian image, dependencies load и полный matrix на выделенных Windows-ПК:
empty Install, duplicate refusal, old-server Reinstall, Remove, failed/timeout
uninstall (без install), missing/corrupt/multiple agent, concurrent requests,
restart/unknown и фактическое подключение в выбранную группу.

Официальные источники: [WinRM 2.4.1 transport](https://github.com/WinRb/WinRM/blob/v2.4.1/lib/winrm/http/transport.rb),
[winrm-fs 1.3.7](https://github.com/WinRb/winrm-fs/tree/v1.3.7),
[MeshAgent installer](https://github.com/Ylianst/MeshAgent/blob/master/modules/agent-installer.js),
[MIT kinit](https://web.mit.edu/kerberos/krb5-latest/doc/user/user_commands/kinit.html),
[Docker Compose secrets](https://docs.docker.com/compose/how-tos/use-secrets/).
WinRM и winrm-fs — Apache-2.0; точные transitive versions/checksums закреплены
в Gemfile.lock. Evil-WinRM shell не запускается и его код не включается в plugin.

## Install (development)

```powershell
# from MeshCentral root
New-Item -ItemType SymbolicLink `
  -Path .\plugins\remoraTerminalBridge `
  -Target "D:\…\RemoraHQ-Terminal-Bridge-Plugins"
```

Then register via `Admin → Plugins → Add` with the `configUrl` from `config.json`.

## License

Apache-2.0 (matches MeshCentral). See `LICENSE`.
