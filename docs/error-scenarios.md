# Ошибочные ситуации и восстановление

Матрица покрывает контракт сервиса, конкурентную работу с PostgreSQL и штатное Docker-развёртывание. Названия ниже указывают на тесты в исходниках; `deploy-check` — отдельный запуск настоящих контейнеров. Сценарии, требующие внешнего резервирования или изменения API, перечислены отдельно.

## HTTP и данные клиента

| Ситуация | Проверяемое поведение | Проверка |
| --- | --- | --- |
| MD5 неверной длины, с не-hex символами или Unicode | `400`, обращений к хранилищу нет; корректный верхний регистр нормализуется | `TestNormalizeMD5`, `TestServiceValidatesBeforeStorageAndPreservesInput`, `FuzzNormalizeMD5` |
| Нет обязательного поля; пустое или слишком длинное имя; неверная severity | `400`, запись не выполняется | `TestStrictJSONAndFieldValidation`, `TestValidateInput` |
| NUL, неверный UTF-8, одиночный UTF-16 surrogate | `400`, исходная строка не заменяется символом подстановки | `TestStrictJSONAndFieldValidation`, `FuzzDecodeObject` |
| `null`, массив, вложенный объект вместо строки, неверный регистр имени поля | `400` | `TestStrictJSONAndFieldValidation`, `FuzzDecodeObject` |
| Повторные ключи, включая экранированное имя; лишний ключ; второй JSON-объект | `400`, вызова хранилища нет | `TestStrictJSONAndFieldValidation` |
| Нет Content-Type, неподдерживаемый charset или сжатие | `415` | `TestMediaTypeBodyLimitAndPriority` |
| Тело больше 65 536 байт, в том числе chunked | `413`, тело не проходит в предметную логику; ровно 65 536 байт допускается при валидном содержимом | `TestMediaTypeBodyLimitAndPriority`, `TestRawChunkedBodiesAndFramingErrors` |
| Повреждённый chunked, конфликтующий или отрицательный Content-Length | `400`, запись не выполняется | `TestRawChunkedBodiesAndFramingErrors` |
| Медленное или незавершённое тело | Чтение ограничено deadline; частичная запись не выполняется. При оборванном транспорте JSON-ответ не гарантируется | `TestRealHTTPBodyReadIsBoundedByRequestDeadline` |
| `Expect: 100-continue` при отклоняемых заголовках | Итоговые `401`, `413` или `415` приходят без ожидания тела | `TestRejectedExpectContinueDoesNotReadBody` |
| Клиент разорвал соединение | Контекст операции отменяется | `TestRealClientDisconnectCancelsService` |
| Неверный маршрут, метод, HEAD или закодированный путь | `404`, `405` с Allow либо `400` для неверного MD5; HEAD без тела | `TestRoutingAndHEADUseRealHTTP` |
| Большой неверный заголовок авторизации или путь с множеством сегментов | Отказ без создания массива под каждое слово/сегмент; регрессионный предел аллокаций проверяется на фиксированных входах | `TestLargeRejectedInputsDoNotAmplifyAllocations` |
| Нет Bearer или токен неверен | `401` с WWW-Authenticate, квота бизнес-запросов не расходуется | `TestOptionalAuthenticationRateLimitAndHealth`, `deploy-check` |
| Исчерпана квота | `429` с Retry-After; отклонённый запрос не резервирует будущую квоту | `TestOptionalAuthenticationRateLimitAndHealth` |
| Частые открытые readiness-пробы | Кеш на 1 секунду и одна общая проверка; ответы 200/503 без 429 от частоты опроса. Бизнес-квота независима, liveness не обращается к БД | `TestReadinessCacheIsIndependentOfBusinessLimiter`, `TestConcurrentReadinessProbesShareOneCheck` |
| Panic или внутренняя ошибка | Безопасный `500`; ERROR-лог сохраняет категорию, request_id и SQLSTATE, для паники — символический стек. Значения секретов и panic payload не раскрываются | `TestRecoveryAndLogsAreSafe`, `TestUnexpectedErrorsHaveCorrelatedSafeDiagnostics`, `TestRepositoryErrorsAreMappedWithoutLeaks` |
| Кеш готовности устарел; БД отказала или восстановилась | После TTL выполняется новая проверка, старый успех не используется бесконечно, ошибка также кешируется | `TestReadinessExpiresSuccessAndFailureThenRecovers` |
| Ожидающий readiness-запрос отменён или истёк | Его ожидание прекращается, общая проверка остаётся доступной другим запросам | `TestCanceledReadinessWaitersDoNotCancelSharedCheck` |
| Deadline или паника readiness-проверки | 503, опубликованный результат и снятый признак in-flight; следующий цикл может восстановиться | `TestReadinessCheckHasItsOwnDeadline`, `TestReadinessPanicPublishesFailureAndStack` |
| Расхождение ручного HTTP с OpenAPI | Проверяются статус, тип, обязательные заголовки и JSON для POST/GET/PUT; мутации ответа обнаруживаются | `TestHTTPContractAgainstOpenAPI`, `TestContractValidatorDetectsResponseRegressions` |

## Записи, транзакции и схема

| Ситуация | Проверяемое поведение | Проверка |
| --- | --- | --- |
| Повторное создание, включая 20 конкурентных запросов | Одна вставка, остальные конфликты; HTTP-преобразование — `409` | `TestConcurrentCreateHasOneWinner`, `TestRepositoryErrorsAreMappedWithoutLeaks` |
| Чтение или PUT отсутствующего MD5 | `404`; PUT не создаёт новую запись | `TestRepositoryCreateGetReplace`, `TestRepositoryErrorsAreMappedWithoutLeaks` |
| В PUT пропущены необязательные поля | Полная замена: description сброшен в пустую строку, severity — unknown | `TestPUTFullReplacementAndPathNormalization` |
| Повтор одинакового PUT | created_at и updated_at остаются прежними | `TestRepositoryCreateGetReplace` |
| Конкурентные PUT и GET | Поля одной возвращённой версии не смешиваются с другой; created_at сохраняется | `TestConcurrentReplaceAndGetNeverMixFields` |
| Вставка другой транзакции ещё не зафиксирована | Незавершённая запись не видна GET/PUT | `TestUncommittedCreateIsInvisibleToGetAndReplace` |
| Строка заблокирована или пул исчерпан | Срабатывает query deadline, включая ожидание соединения; отменённый заблокированный PUT позже не записывает данные | `TestBlockedReplaceTimesOutWithoutDelayedWrite`, `TestQueryTimeoutIncludesWaitingForPool` |
| Повторные отмены на одном backend PostgreSQL | Пять циклов отмены/повторного использования проходят без отмены следующего запроса и без обязательной замены здорового соединения | `TestCanceledQueryDoesNotCancelNextUseOfSameConnection` |
| Ошибка или одновременный запуск миграций | Ошибочная транзакция не оставляет версию; конкурентное применение выполняется один раз; down/up обратимы | `TestFailedMigrationDoesNotRecordVersion`, `TestConcurrentMigrationsApplyOnce`, `TestMigrationsAreVersionedAndReversible` |
| Неверные значения внесены напрямую в БД | Ограничения PostgreSQL отклоняют проверяемые строки | `TestDatabaseConstraintsRejectInvalidRows` |
| Версия есть, но схема изменилась | Новый Check и повторный up завершаются ошибкой; автоматического удаления или исправления данных нет | `TestSchemaDriftFailsCheckAndUpWithoutRepair` — 11 вариантов |
| В search_path несколько схем; есть временные одноимённые таблицы | Работа ведётся только с выбранной постоянной схемой; миграции не заимствуют чужие таблицы | `TestSearchPathDoesNotBorrowSchemaFromLaterEntry`, `TestTemporaryTablesCannotShadowMigrationTargets` |
| Целевая таблица или схема удалена, соединение переподключилось | Репозиторий не переключается на записи следующей схемы или temp-таблицы; проверка готовности отклоняет несовместимую схему | `TestRuntimeNeverFallsBackAfterTargetDisappears` |
| Миграция удерживает advisory lock | Readiness ждёт в рамках deadline, после отката снова проходит | `TestReadinessWaitsForMigrationLockWithinDeadline` |
| У runtime-роли отозван INSERT или UPDATE | Новая проверка готовности отклоняется; после восстановления прав проверка и создание работают. HTTP-кеш обновляется после TTL | `TestReadinessRejectsMissingRuntimePrivileges` |
| Runtime-роль не существует при up | Схема применена, выдача прав не выполнена; ошибка явно описывает состояние. После создания роли повторный up выдаёт права | `TestRuntimeGrantsUseTargetSchemaAndRecoverAfterMissingRole`, `deploy-check` |
| Нестандартная схема или кавычка в имени роли | Идентификаторы корректно экранируются; права выдаются выбранной схеме; владельца нельзя выдать за ограниченную runtime-роль | `TestRuntimeGrantsUseTargetSchemaAndRecoverAfterMissingRole` |

## Запуск и эксплуатация

| Ситуация | Проверяемое поведение | Проверка |
| --- | --- | --- |
| Неверные тайм-ауты, NaN rate, порт, размер пула, token68 или переполнение WriteTimeout | Процесс отказывается стартовать; значения настроек не печатаются | `TestInvalidConfigurationDoesNotRevealValues`, `deploy-check` |
| Неизвестный аргумент мигратора или down без защитной переменной | Отказ до соединения с БД; значения аргументов не раскрываются | `TestInvalidArgumentsFailBeforeDatabaseAccess`, `TestDestructiveGuardPrecedesDatabaseConnection` |
| Неверный пароль мигратора | Код процесса 1; connect_database, authentication_failed и SQLSTATE 28P01 без DSN и пароля | `TestMigrationDiagnosticsAgainstPostgres`, `TestMigrationFailureRetainsOnlySafeMetadata` |
| Несовместимая схема при status/up/down | check_schema и schema_mismatch; названия объектов не попадают в лог, схема автоматически не исправляется | `TestMigrationDiagnosticsAgainstPostgres` |
| Runtime-роль не существует или небезопасна | grant_runtime_role и runtime_role_missing/runtime_role_unsafe; схема уже применена, имя роли не раскрывается | `TestRuntimeGrantsUseTargetSchemaAndRecoverAfterMissingRole`, `TestMigrationFailureRetainsOnlySafeMetadata` |
| Ошибка SQL при применении миграции | apply_migration, категория postgresql и исходная SQLSTATE; Message/Detail/Hint и SQL-параметры не раскрываются | `TestMigrationDiagnosticsAgainstPostgres`, `TestMigrationFailureRetainsOnlySafeMetadata` |
| Порт занят, DSN повреждён, PEM недоступен | Безопасная ошибка старта без DSN, пароля и путей к секретным файлам | `TestStartupFailuresReturnSafeErrors` |
| SIGTERM при активной записи | При достаточном времени запрос заканчивается; при истечении shutdown deadline SQL отменяется, поздней записи нет | `TestServerDrainsOrCancelsActiveSQLWithinShutdownBudget` |
| PostgreSQL недоступна | Liveness — `200`, readiness — `503`, запись — безопасный `500`. После запуска БД тот же процесс обслуживает запросы | `deploy-check` |
| Пересборка и повторный up | Данные и даты прежние; используется существующий том | `deploy-check` |
| Пароль содержит `:@/?#%$`, пробел и кавычку | Bootstrap и API работают, пароль передаётся через PGPASSWORD, секреты не попадают в проверяемый вывод | `deploy-check` |
| Пароль явно пустой на новом томе | Bootstrap завершается ошибкой, приложение не запускается | `deploy-check` |
| Ключ не читается UID 65532 | Приложение отказывается стартовать; с доступной парой PEM работает HTTPS с проверкой доверия | `deploy-check` |
| Уязвимая версия Go или модуля | Закреплены Go 1.27.3 и исправленная x/text v0.41.0; сканер проверяет весь граф приложения | `make vuln` |

## Границы гарантий

- Разрыв сети около COMMIT может оставить результат записи неизвестным. Автоматических повторов нет. GET показывает текущее состояние, но не доказывает, какой конкурентный запрос его записал.
- В исходном API нет версии записи и If-Match: последняя замена может затереть предыдущую. Без изменения контракта это допустимая семантика полной замены.
- Проверка схемы доверяет её владельцу и не доказывает смысл CHECK, если администратор заменил выражение с сохранением имени и колонок. DDL следует изменять через миграции.
- Повреждение диска, потеря хоста, удаление тома и восстановление из резервной копии требуют отдельной эксплуатационной инфраструктуры. Репликация и backup-сервис в тестовое задание не входят.
- Аллокационные проверки и fuzz-прогоны конечны. Они выявляют регрессии и ошибки на исследованных входах; исчерпывающее доказательство для всех входов, нагрузок и сбоев не заявляется.
