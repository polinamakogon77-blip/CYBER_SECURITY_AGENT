

# Отчёт: анализ `/app/juice-shop/routes/search.ts`

## Задача
Статический анализ одного файла (`/app/juice-shop/routes/search.ts`) на предмет SQL-инъекции. Динамические проверки не выполнялись по требованию.

## Что сделано
- Вызван `read_file_around_line` для `/app/juice-shop/routes/search.ts` (строка 1, контекст 150 000 символов) — прочитан весь файл (74 строки).
- Проведён ручной анализ: источник пользовательского ввода, путь данных до SQL-запроса, наличие санитизации/параметризации.
- Другие инструменты не запускались.

## Результаты

### 1. SQL-инъекция в обработчике `searchProducts`
- **Категория:** SQL Injection (union-based)
- **Severity:** CRITICAL
- **Локация:** `/app/juice-shop/routes/search.ts:23`
- **Статус:** confirmed (статический анализ)
- **Доказательство (фактический код):**
  ```ts
  // строки 21–23
  let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
  criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
  models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
  ```
- **Анализ:**
  - Источник: `req.query.q` (GET-параметр `q`) — полностью контролируемый пользователем ввод.
  - Ввод подставляется в SQL-запрос напрямую через шаблонную строку (string interpolation) без параметризации и без экранирования.
  - Единственная «защита» — обрезка до 200 символов (строка 22), что **не предотвращает** инъекцию: для UNION-инъекции достаточно короткого payload.
  - Запрос выполняется через `models.sequelize.query()` (сырой SQL), а не через параметризованный API Sequelize.
  - В коде присутствуют маркеры `vuln-code-snippet vuln-line unionSqlInjectionChallenge dbSchemaChallenge` — уязвимость намеренно заложена в учебном стенде (челленджи «Union SQL Injection» и «DB Schema»).
  - Потенциальное влияние: чтение данных из других таблиц (в т.ч. `Users` — email/пароли) через `UNION SELECT`, извлечение схемы БД.
- **Ограничения проверки:** анализ только по исходному коду; динамическая эксплуатация (UNION-запрос к живой БД) по заданию не выполнялась, поэтому подтверждение — на уровне кода.
- **Рекомендация:**
  - Использовать параметризованный запрос:
    ```ts
    models.sequelize.query(
      'SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name',
      { replacements: { criteria: `%${criteria}%` } }
    )
    ```
  - Дополнительно: экранировать LIKE-wildcards (`%`, `_`) в пользовательском вводе, минимизировать права учётной записи БД, включить WAF/валидацию формата параметра `q`.

## Выводы
- **Подтверждено:** в файле `/app/juice-shop/routes/search.ts` (строка 23) существует SQL-инъекция — пользовательский параметр `q` конкатенируется в raw SQL-запрос без параметризации. Критичность — CRITICAL.
- **Требует дополнительной проверки:** фактическая эксплуатация на живом стенде (не выполнялась по заданию).
- **Приоритет исправления:** немедленный — переход на prepared statement с `replacements` в `searchProducts`.
- В отчёт включена единственная накопленная структурированная находка; новых находок в рамках анализа этого файла не выявлено.