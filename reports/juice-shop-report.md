# Security Report
Generated: 2026-11-25T14:15:43.197265Z
Total findings: 25

## 1. SQL injection in login
- **Severity:** CRITICAL
- **Category:** N/A
- **Evidence:** models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
- **Recommendation:** Использовать параметризованный запрос или ORM-запрос, например UserModel.findOne({ where: { email: req.body.email || '', password: security.hash(req.body.password || '') } }).

## 2. SQL-инъекция в форме входа
- **Severity:** CRITICAL
- **Category:** N/A
- **Evidence:** payload: {"email": "' OR 1=1--", "password": "1234567890"}
status: 200
body: {"authentication":{"token":"[замаскирован]"}}
- **Recommendation:** Использовать параметризованные запросы для проверки учётных данных, хранить пароли в виде хешей и проверять их на сервере.

## 3. SQL-инъекция: запрос собирается через шаблонную строку
- **Severity:** HIGH
- **Category:** N/A
- **Evidence:** check_id=rules.sqli-template-string-query; path=/app/juice-shop/data/static/codefixes/dbSchemaChallenge_3.ts; line=11; message='SQL-инъекция: запрос собирается через шаблонную строку с интерполяцией. Используйте параметризованны'; snippet='requires login'
- **Recommendation:** Просмотреть файл и заменить сборку SQL через шаблонную строку на параметризованный запрос или ORM-метод с параметрами.

## 4. SQL-инъекция: запрос собирается через шаблонную строку
- **Severity:** HIGH
- **Category:** N/A
- **Evidence:** check_id=rules.sqli-template-string-query; path=/app/juice-shop/data/static/codefixes/unionSqlInjectionChallenge_1.ts; line=6; message='SQL-инъекция: запрос собирается через шаблонную строку с интерполяцией. Используйте параметризованны'; snippet='requires login'
- **Recommendation:** Просмотреть файл и заменить сборку SQL через шаблонную строку на параметризованный запрос или ORM-метод с параметрами.

## 5. SQL-инъекция: запрос собирается через шаблонную строку
- **Severity:** HIGH
- **Category:** N/A
- **Evidence:** check_id=rules.sqli-template-string-query; path=/app/juice-shop/data/static/codefixes/unionSqlInjectionChallenge_3.ts; line=10; message='SQL-инъекция: запрос собирается через шаблонную строку с интерполяцией. Используйте параметризованны'; snippet='requires login'
- **Recommendation:** Просмотреть файл и заменить сборку SQL через шаблонную строку на параметризованный запрос или ORM-метод с параметрами.

## 6. SQL injection in product search
- **Severity:** HIGH
- **Category:** N/A
- **Evidence:** models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
- **Recommendation:** Использовать параметризованный запрос с bind-параметрами, например sequelize.query('SELECT * FROM Products WHERE (name LIKE :q OR description LIKE :q) AND deletedAt IS NULL ORDER BY name', { bind: { q: '%' + criteria + '%' } }).

## 7. SQL-инъекция в поиске товаров
- **Severity:** HIGH
- **Category:** N/A
- **Evidence:** payload: ' UNION SELECT id, email, password, totpSecret, role, deletedAt, createdAt, updatedAt, 1 FROM Users--
status: 500
body: Error: SQLITE_ERROR: near "UNION": syntax error
- **Recommendation:** Использовать параметризованные запросы, валидировать входные данные и не возвращать подробные ошибки СУБД.

## 8. Доступ к конфиденциальному документу acquisitions.md
- **Severity:** HIGH
- **Category:** N/A
- **Evidence:** # Planned Acquisitions

> This document is confidential! Do not distribute!
- **Recommendation:** Убрать чувствительные файлы из web-root или защитить их аутентификацией.

## 9. Unprotected Admin API (/api/Users)
- **Severity:** HIGH
- **Category:** N/A
- **Evidence:** {"status":"success","data":[{"id":1,"email":"admin@juice-sh.op","role":"admin"},{"id":2,"email":"jim@juice-sh.op","role":"customer"}]}
- **Recommendation:** Добавить проверку role === 'admin' в middleware.

## 10. Подозрение на наличие уязвимого приложения OWASP Juice Shop
- **Severity:** MEDIUM
- **Category:** N/A
- **Evidence:** В каталоге /app/juice-shop перечислены файлы app.ts, server.ts, package.json, frontend/, config/, swagger.yml, ctf.key и другие, характерные для проекта OWASP Juice Shop.
- **Recommendation:** Проверить, запущено ли приложение, его сетевую доступность и конфигурацию; ограничить доступ, если оно используется только для обучения или CTF.

## 11. Подозрение на SQL-инъекцию в sqli-lab
- **Severity:** MEDIUM
- **Category:** N/A
- **Evidence:** В каталоге /app/sqli-lab перечислены файлы app.py, init_db.py, lab_database.db, templates/index.html, Dockerfile, requirements.txt.
- **Recommendation:** Проверить код app.py и init_db.py, формирование SQL-запросов, параметры и доступность сервиса (при наличии разрешения на этот стенд).

## 12. Подозрение на NoSQL-инъекцию в nosqli-lab
- **Severity:** MEDIUM
- **Category:** N/A
- **Evidence:** В каталоге /app/nosqli-lab перечислены файлы app.py, init_db.py, entrypoint.sh, templates/index.html, Dockerfile, requirements.txt.
- **Recommendation:** Проверить код app.py и init_db.py, обработку запросов к NoSQL-хранилищу и доступность сервиса (при наличии разрешения на этот стенд).

## 13. Подозрение на LFI/RFI в target
- **Severity:** MEDIUM
- **Category:** N/A
- **Evidence:** В каталоге /app/target перечислены файлы LFI_RFI_remote.py, LFI_RFI_service.py, fi_private_page.py и fi_pages/welcome.py.
- **Recommendation:** Проверить реализацию include/read, обработку пользовательских параметров, доступность сервиса и наличие ограничений путей (при наличии разрешения на этот стенд).

## 14. Подозрение на SSRF в target
- **Severity:** MEDIUM
- **Category:** N/A
- **Evidence:** В каталоге /app/target перечислены файлы SSRF_app.py, SSRF_service.py, SSRF_streamlit_app.py и Dockerfile.ssrf-flask.
- **Recommendation:** Проверить обработку URL и внешних запросов, наличие allowlist, блокировку внутренних адресов и доступность сервиса (при наличии разрешения на этот стенд).

## 15. Возможный IDOR: загрузка объекта по ID без проверки владельца
- **Severity:** MEDIUM
- **Category:** N/A
- **Evidence:** check_id=rules.idor-findone-no-owner-check; path=/app/juice-shop/routes/address.ts; line=18; message='Возможен IDOR: объект загружается по req.params.id без проверки владельца. Убедитесь, что текущий по'; snippet='requires login'
- **Recommendation:** Просмотреть обработчик и убедиться, что перед возвратом объекта проверяется его принадлежность текущему пользователю или выполняется соответствующая авторизация.

## 16. Возможный IDOR: загрузка объекта по ID без проверки владельца
- **Severity:** MEDIUM
- **Category:** N/A
- **Evidence:** check_id=rules.idor-findone-no-owner-check; path=/app/juice-shop/routes/basketItems.ts; line=68; message='Возможен IDOR: объект загружается по req.params.id без проверки владельца. Убедитесь, что текущий по'; snippet='requires login'
- **Recommendation:** Просмотреть обработчик и убедиться, что перед возвратом объекта проверяется его принадлежность текущему пользователю или выполняется соответствующая авторизация.

## 17. Возможный IDOR: загрузка объекта по ID без проверки владельца
- **Severity:** MEDIUM
- **Category:** N/A
- **Evidence:** check_id=rules.idor-findone-no-owner-check; path=/app/juice-shop/routes/delivery.ts; line=34; message='Возможен IDOR: объект загружается по req.params.id без проверки вл'; snippet='requires login'
- **Recommendation:** Просмотреть обработчик и убедиться, что перед возвратом объекта проверяется его принадлежность текущему пользователю или выполняется соответствующая авторизация.

## 18. Открытый листинг директории /ftp/
- **Severity:** MEDIUM
- **Category:** N/A
- **Evidence:** <title>listing directory /ftp/</title>
- **Recommendation:** Отключить autoindex / directory listing.

## 19. Возможный IDOR / нарушение контроля доступа в маршрутах address
- **Severity:** MEDIUM
- **Category:** N/A
- **Evidence:** AddressModel.findAll({ where: { UserId: req.body.UserId } }); AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } }); AddressModel.destroy({ where: { id: req.params.id, UserId: req.body.UserId } })
- **Recommendation:** Использовать идентификатор пользователя из проверенной сессии/JWT, а не из тела запроса; добавить проверку владения записью; проверить доступность маршрутов и middleware.

## 20. Отсутствуют защитные HTTP-заголовки
- **Severity:** LOW
- **Category:** N/A
- **Evidence:** [MISSING] CSP
[MISSING] HSTS
[OK] X-Frame-Options: SAMEORIGIN
[OK] X-Content-Type-Options: nosniff
[MISSING] Referrer-Policy
[MISSING] Permissions-Policy
[MISSING] X-XSS-Protection (legacy)
- **Recommendation:** Добавить соответствующие защитные заголовки в соответствии с политикой безопасности приложения.

## 21. security.txt опубликован
- **Severity:** LOW
- **Category:** N/A
- **Evidence:** Contact: mailto:donotreply@owasp-juice.shop
Expires: Thu, 25 Nov 2027 12:46:08 GMT
- **Recommendation:** Поддерживать contact/expires в актуальном состоянии.

## 22. Публичный Swagger API (информационное раскрытие)
- **Severity:** LOW
- **Category:** N/A
- **Evidence:** Nuclei template swagger-api matched at http://juice-shop:3000/api-docs/swagger.json with HTTP 200 OK. Response headers include Access-Control-Allow-Origin: * and Content-Type: text/html; charset=utf-8.
- **Recommendation:** Restrict access to /api-docs/swagger.json in production, remove it, or protect it with authentication.

## 23. Forged review / XSS (не подтверждено)
- **Severity:** LOW
- **Category:** N/A
- **Evidence:** status=201, forged_ok=False, xss_ok=False
- **Recommendation:** Manually verify whether an unauthenticated or forged review can be created and whether any review content is rendered without sanitization.

## 24. Возможный XXE в загрузке файла (не подтверждено)
- **Severity:** LOW
- **Category:** N/A
- **Evidence:** Attempts with file:///etc/hostname, file:///etc/passwd and file:///c:/windows/win.ini returned HTTP 500. Body preview: Error: WHERE parameter "captchaId" has invalid "undefined" value. No file contents were returned.
- **Recommendation:** Retry with a valid captchaId and safe XML payloads, and verify that the XML parser disables external entities and file:// access.

## 25. Раскрытие информации в ответе 500: stack trace, внутренние пути и версия приложения
- **Severity:** LOW
- **Category:** N/A
- **Evidence:** status=500; body contains: <h1>OWASP Juice Shop (Express ^4.22.1)</h1>, <h2><em>500</em> Error: Unexpected path: /rest/user/register</h2>, stacktrace entries such as /juice-shop/build/routes/angular.js:18:18 and /juice-shop/build/lib/utils.js:235:26
- **Recommendation:** В production отключать подробные сообщения об ошибках, возвращать общий ответ 500 и логировать детали на сервере. Убрать версию приложения из ответа.
