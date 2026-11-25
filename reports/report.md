# 🛡️ Отчет о проверке безопасности
**Дата генерации:** 2026-11-25T19:09:38.436277Z
**Всего находок:** 26

---

## 1. SQL-инъекция в login
- **Критичность:** CRITICAL
- **Категория:** N/A
- **Доказательства:**
  ```
  models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
  ```
- **Рекомендация:** Использовать параметризованный запрос или bind-параметры Sequelize, например: WHERE email = :email AND password = :password.

---

## 2. SQL-инъекция в searchProducts (codefix-файл)
- **Критичность:** CRITICAL
- **Категория:** N/A
- **Доказательства:**
  ```
  let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    criteria.replace(/"|'|;|and|or/i, "")
    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
  ```
- **Рекомендация:** Использовать параметризованный запрос или безопасный поиск через ORM, а не конкатенацию пользовательского ввода в SQL.

---

## 3. Потенциальная SQL-инъекция в компоненте sqli-lab
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  В каталоге /app обнаружен компонент sqli-lab с файлами app.py, init_db.py и lab_database.db. Содержимое файлов и SQL-запросы в предоставленных результатах отсутствуют, поэтому факт уязвимости не подтвержден.
  ```
- **Рекомендация:** Проверить исходный код sqli-lab/app.py и init_db.py, использовать параметризованные запросы, выполнить динамическое тестирование.

---

## 4. Потенциальная NoSQL-инъекция в компоненте nosqli-lab
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  В каталоге /app обнаружен компонент nosqli-lab с файлами app.py, init_db.py и entrypoint.sh. Содержимое файлов и запросы к NoSQL-хранилищу в предоставленных результатах отсутствуют, поэтому факт уязвимости не подтвержден.
  ```
- **Рекомендация:** Проверить исходный код nosqli-lab/app.py и init_db.py, валидировать и экранировать пользовательский ввод, выполнить динамическое тестирование.

---

## 5. Потенциальная LFI/RFI в компоненте target
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  В каталоге /app/target обнаружены файлы LFI_RFI_remote.py, LFI_RFI_service.py, fi_pages/welcome.py и fi_private_page.py. Содержимое файлов и логика включения файлов в предоставленных результатах отсутствуют, поэтому факт уязвимости не подтвержден.
  ```
- **Рекомендация:** Проверить исходный код target/LFI_RFI_remote.py и target/LFI_RFI_service.py, ограничить разрешенные пути, запретить удаленные источники, выполнить динамическое тестирование.

---

## 6. Потенциальный SSRF в компоненте target
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  В каталоге /app/target обнаружены файлы SSRF_app.py, SSRF_service.py, SSRF_streamlit_app.py и Dockerfile.ssrf-flask. Содержимое файлов и логика формирования исходящих запросов в предоставленных результатах отсутствуют, поэтому факт уязвимости не подтвержден.
  ```
- **Рекомендация:** Проверить исходный код target/SSRF_app.py и target/SSRF_service.py, использовать allowlist URL, блокировать внутренние адреса, выполнить динамическое тестирование.

---

## 7. Наличие потенциально уязвимого учебного приложения Juice Shop
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  В каталоге /app обнаружен компонент juice-shop с файлами package.json, config/unsafe.yml, README.md и Dockerfile. Название и структура каталога указывают на приложение Juice Shop, которое может быть намеренно уязвимым учебным приложением; доступность и конфигурация не подтверждены.
  ```
- **Рекомендация:** Проверить, является ли компонент Juice Shop, изолировать от production-сетей, ограничить доступ, проверить config/unsafe.yml и не использовать небезопасные конфигурации в рабочей среде.

---

## 8. SQL-инъекция: запрос собирается через шаблонную строку (требует верификации)
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  Инструмент вернул finding: check_id=rules.sqli-template-string-query, path=/app/juice-shop/data/static/codefixes/dbSchemaChallenge_3.ts, line=11, severity=ERROR, message='SQL-инъекция: запрос собирается через шаблонную строку с интерполяцией. Используйте параметризованны', snippet='requires login'.
  ```
- **Рекомендация:** Получить исходный код строки 11 и проверить, попадает ли пользовательский ввод в SQL-запрос. При подтверждении использовать параметризованный запрос или безопасный ORM-метод.

---

## 9. SQL-инъекция: запрос собирается через шаблонную строку (требует верификации)
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  Инструмент вернул finding: check_id=rules.sqli-template-string-query, path=/app/juice-shop/data/static/codefixes/unionSqlInjectionChallenge_1.ts, line=6, severity=ERROR, message='SQL-инъекция: запрос собирается через шаблонную строку с интерполяцией. Используйте параметризованны', snippet='requires login'.
  ```
- **Рекомендация:** Получить исходный код строки 6 и проверить, попадает ли пользовательский ввод в SQL-запрос. При подтверждении использовать параметризованный запрос или безопасный ORM-метод.

---

## 10. SQL-инъекция: запрос собирается через шаблонную строку (требует верификации)
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  Инструмент вернул finding: check_id=rules.sqli-template-string-query, path=/app/juice-shop/data/static/codefixes/unionSqlInjectionChallenge_3.ts, line=10, severity=ERROR, message='SQL-инъекция: запрос собирается через шаблонную строку с интерполяцией. Используйте параметризованны', snippet='requires login'.
  ```
- **Рекомендация:** Получить исходный код строки 10 и проверить, попадает ли пользовательский ввод в SQL-запрос. При подтверждении использовать параметризованный запрос или безопасный ORM-метод.

---

## 11. SQL-инъекция в поиске товаров
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
  ```
- **Рекомендация:** Использовать параметризованный запрос Sequelize с bind-параметрами или ORM-запрос с where и Op.like. Не собирать SQL-строку конкатенацией пользовательского ввода.

---

## 12. Возможный IDOR в адресной книге
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  const addresses = await AddressModel.findAll({ where: { UserId: req.body.UserId } })
  ```
- **Рекомендация:** Использовать идентификатор пользователя из аутентифицированного контекста, а не из тела запроса. Для операций с id дополнительно проверять, что ресурс принадлежит текущему пользователю.

---

## 13. Возможный IDOR в платёжных методах
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  const cards = await CardModel.findAll({ where: { UserId: req.body.UserId } })
  ```
- **Рекомендация:** Использовать UserId из аутентифицированного контекста. Для getPaymentMethodById проверять, что карта принадлежит текущему пользователю. Ограничить возвращаемые поля.

---

## 14. NoSQL/JS-инъекция в $where при чтении отзывов
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  const id = !utils.isChallengeEnabled(challenges.noSqlCommandChallenge) ? Number(req.params.id) : utils.trunc(req.params.id, 40); db.reviewsCollection.find({ $where: 'this.product == ' + id })
  ```
- **Рекомендация:** Не использовать $where с пользовательским входом. Валидировать id как число и использовать безопасный фильтр, например { product: Number(req.params.id) }.

---

## 15. Path traversal / Zip Slip при распаковке ZIP-файла
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  const fileName = entry.path; const absolutePath = path.resolve('uploads/complaints/' + fileName); challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return absolutePath === path.resolve('ftp/legal.md') }); if (absolutePath.includes(path.resolve('.'))) { await pipeline(entry.stream(), fs.createWriteStream('uploads/complaints/' + fileName)) }
  ```
- **Рекомендация:** Проверять, что path.resolve('uploads/complaints', fileName) начинается с path.resolve('uploads/complaints') + path.sep; отклонять пути с ../ и абсолютные пути; использовать безопасную распаковку.

---

## 16. NoSQL-инъекция в update отзывов через req.body.id
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  { _id: req.body.id }, { multi: true }, challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modified > 1 })
  ```
- **Рекомендация:** Валидировать id как строку/ObjectId, использовать безопасный фильтр, например { _id: new ObjectId(req.body.id) } или { _id: String(req.body.id) }, ограничить multi.

---

## 17. Отсутствие проверки владельца при обновлении отзыва
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  const user = security.authenticatedUsers.from(req); { _id: req.body.id }, challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user?.data && result.original[0] && result.original[0].author !== user.data.email && result.modified === 1 })
  ```
- **Рекомендация:** Перед обновлением получить документ и проверить, что author совпадает с email текущего пользователя; при несовпадении вернуть 403.

---

## 18. Возможное отсутствие аутентификации в обработчике обновления отзыва
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  const user = security.authenticatedUsers.from(req); db.reviewsCollection.update(
  ```
- **Рекомендация:** Добавить явную проверку user и вернуть 401, либо убедиться, что маршрут защищён middleware аутентификации.

---

## 19. Потенциальное наличие чувствительных файлов и небезопасной конфигурации
- **Критичность:** MEDIUM
- **Категория:** N/A
- **Доказательства:**
  ```
  В каталоге /app/juice-shop обнаружены файлы ctf.key, .npmrc и config/unsafe.yml. Содержимое файлов в предоставленных результатах отсутствует, поэтому факт наличия секретов или небезопасных настроек не подтвержден.
  ```
- **Рекомендация:** Проверить содержимое ctf.key, .npmrc и config/unsafe.yml, исключить публикацию секретов, использовать хранилище секретов и ограничить доступ к конфигурационным файлам.

---

## 20. Возможный IDOR: загрузка объекта по req.params.id без подтверждённой проверки владельца
- **Критичность:** MEDIUM
- **Категория:** N/A
- **Доказательства:**
  ```
  Инструмент вернул finding: check_id=rules.idor-findone-no-owner-check, path=/app/juice-shop/routes/address.ts, line=18, severity=WARNING, message='Возможен IDOR: объект загружается по req.params.id без проверки владельца. Убедитесь, что текущий по', snippet='requires login'.
  ```
- **Рекомендация:** Получить исходный код обработчика и проверить, сопоставляется ли id с владельцем/сессией текущего пользователя. При подтверждении добавить проверку владельца до возврата объекта.

---

## 21. Возможный IDOR: загрузка объекта по req.params.id без подтверждённой проверки владельца
- **Критичность:** MEDIUM
- **Категория:** N/A
- **Доказательства:**
  ```
  Инструмент вернул finding: check_id=rules.idor-findone-no-owner-check, path=/app/juice-shop/routes/basketItems.ts, line=68, severity=WARNING, message='Возможен IDOR: объект загружается по req.params.id без проверки владельца. Убедитесь, что текущий по', snippet='requires login'.
  ```
- **Рекомендация:** Получить исходный код обработчика и проверить, сопоставляется ли id с владельцем/сессией текущего пользователя. При подтверждении добавить проверку владельца до возврата объекта.

---

## 22. Возможный IDOR: загрузка объекта по req.params.id без подтверждённой проверки владельца
- **Критичность:** MEDIUM
- **Категория:** N/A
- **Доказательства:**
  ```
  Инструмент вернул finding: check_id=rules.idor-findone-no-owner-check, path=/app/juice-shop/routes/delivery.ts, line=34, severity=WARNING, message='Возможен IDOR: объект загружается по req.params.id без проверки вл', snippet='requires login'.
  ```
- **Рекомендация:** Получить исходный код обработчика и проверить, сопоставляется ли id с владельцем/сессией текущего пользователя. При подтверждении добавить проверку владельца до возврата объекта.

---

## 23. Возможная манипуляция корзиной из-за несогласованной валидации BasketId
- **Критичность:** MEDIUM
- **Категория:** N/A
- **Доказательства:**
  ```
  if (user && basketIds[0] && basketIds[0] !== 'undefined' && Number(user.bid) != Number(basketIds[0])) {
  ```
- **Рекомендация:** Валидировать все переданные BasketId или использовать единственный параметр. Отклонять запросы, если хотя бы один BasketId не совпадает с user.bid.

---

## 24. Подделка автора отзыва в createProductReviews
- **Критичность:** MEDIUM
- **Категория:** N/A
- **Доказательства:**
  ```
  const user = security.authenticatedUsers.from(req)
    challengeUtils.solveIf(
      challenges.forgedReviewChallenge,
      () => user?.data?.email !== req.body.author
    )

    try {
      await reviewsCollection.insert({
        product: req.params.id,
        message: req.body.message,
        author: req.body.author,
  ```
- **Рекомендация:** Использовать e-mail аутентифицированного пользователя как author или валидировать, что req.body.author совпадает с user.data.email.

---

## 25. Возможный open redirect через query.to
- **Критичность:** MEDIUM
- **Категория:** N/A
- **Доказательства:**
  ```
  const toUrl: string = query.to as string; if (security.isRedirectAllowed(toUrl)) { ... res.redirect(toUrl) }
  ```
- **Рекомендация:** Использовать строгий allowlist доменов/URL, валидировать scheme и host, не редиректить на произвольный пользовательский URL.

---

## 26. Возможная утечка информации в ответе об ошибке
- **Критичность:** LOW
- **Категория:** N/A
- **Доказательства:**
  ```
  res.status(500).json(err)
  ```
- **Рекомендация:** Возвращать клиенту обобщённое сообщение, логировать детали на сервере.

---
