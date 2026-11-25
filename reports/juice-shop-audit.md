# 🛡️ Отчет о проверке безопасности
**Дата генерации:** 2026-11-25T14:58:18.110613Z
**Всего находок:** 31

---

## 1. Захардкоженный RSA-приватный ключ
- **Критичность:** CRITICAL
- **Категория:** N/A
- **Доказательства:**
  ```
  const privateKey = '-----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----' (lib/insecurity.ts:21). Используется в authorize() для подписи JWT (RS256).
  ```
- **Рекомендация:** Удалить ключ из кода, использовать переменные окружения/secret manager, сгенерировать новый ключ и отозвать ранее выпущенные токены.

---

## 2. Возможное хранение секретного ключа в файле ctf.key
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  В выводе каталога присутствует файл ctf.key. Попытка чтения вернула 'чтение файла запрещено', поэтому содержимое не подтверждено.
  ```
- **Рекомендация:** Проверить содержимое ctf.key. Если это секрет: удалить из репозитория, ротировать ключ, хранить в secret manager, добавить secret scanning в CI/CD.

---

## 3. SQL-инъекция в dbSchemaChallenge_3.ts
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  Semgrep (rules.sqli-template-string-query): SQL-запрос собирается через шаблонную строку с интерполяцией. Файл data/static/codefixes/dbSchemaChallenge_3.ts:11.
  ```
- **Рекомендация:** Проверить, используется ли файл в рантайме; заменить интерполяцию на параметризованный запрос.

---

## 4. SQL-инъекция в unionSqlInjectionChallenge_1.ts
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  Semgrep (rules.sqli-template-string-query): SQL-запрос собирается через шаблонную строку. Файл data/static/codefixes/unionSqlInjectionChallenge_1.ts:6.
  ```
- **Рекомендация:** Проверить использование в рантайме; заменить на параметризованный запрос.

---

## 5. SQL-инъекция в unionSqlInjectionChallenge_3.ts
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  Semgrep (rules.sqli-template-string-query): SQL-запрос собирается через шаблонную строку. Файл data/static/codefixes/unionSqlInjectionChallenge_3.ts:10.
  ```
- **Рекомендация:** Проверить использование в рантайме; заменить на параметризованный запрос.

---

## 6. SQL-инъекция в login (routes/login.ts)
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
  ```
- **Рекомендация:** Использовать параметризованный запрос или ORM-методы с where-условиями.

---

## 7. SQL-инъекция в searchProducts (routes/search.ts)
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
  ```
- **Рекомендация:** Использовать параметризованный запрос или ORM-методы с where-условиями.

---

## 8. Потенциальный path traversal / null-byte в servePublicFiles
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  if (!file.includes('/')) { verify(file, res, next) } ... file = security.cutOffPoisonNullByte(file) ... res.sendFile(path.resolve('ftp/', file)). Разрешены .md/.pdf и incident-support.kdbx.
  ```
- **Рекомендация:** Нормализовать путь, использовать path.basename, проверять, что итоговый путь внутри ftp/, запрещать null-byte и разделители.

---

## 9. Потенциальный path traversal / произвольное чтение в serveLogFiles
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  if (!file.includes('/')) { res.sendFile(path.resolve('logs/', file)) }
  ```
- **Рекомендация:** Ограничить имена файлов, использовать path.basename, проверять, что итоговый путь внутри logs/, запрещать null-byte.

---

## 10. Хранение паролей в виде MD5-хэшей
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex') — используется в login.ts для сравнения паролей.
  ```
- **Рекомендация:** Использовать bcrypt/argon2/scrypt с индивидуальной солью.

---

## 11. Захардкоженный HMAC-ключ
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')
  ```
- **Рекомендация:** Перенести ключ в переменные окружения/secret manager.

---

## 12. Слабые и раскрытые учётные данные в коде
- **Критичность:** HIGH
- **Категория:** N/A
- **Доказательства:**
  ```
  verifyPreLoginChallenges содержит пары: admin@.../admin123, support@.../J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P, mc.safesearch@.../Mr. N00dles, amy@.../K1f..., testing@.../IamUsedForTesting.
  ```
- **Рекомендация:** Удалить учётные данные из кода, использовать strong passwords, хранить в БД/secret manager.

---

## 13. Возможные небезопасные конфигурации в config/*.yml
- **Критичность:** MEDIUM
- **Категория:** N/A
- **Доказательства:**
  ```
  В каталоге config присутствуют unsafe.yml, ctf.yml, default.yml, test.yml, tutorial.yml и др. unsafe.yml содержит 'challenges: safetyMode: disabled'; default.yml содержит baseUrl, securityTxt, chatBot (llmApiUrl http://localhost:11434/v1) и другие параметры.
  ```
- **Рекомендация:** Проверить активный профиль конфигурации; отключить unsafe/ctf профили в production, ограничить доступ к конфигурации.

---

## 14. Возможный IDOR в address.ts
- **Критичность:** MEDIUM
- **Категория:** N/A
- **Доказательства:**
  ```
  Semgrep (rules.idor-findone-no-owner-check): объект загружается по req.params.id без проверки владельца. Файл routes/address.ts:18.
  ```
- **Рекомендация:** Проверить наличие owner check и аутентификации; добавить проверку принадлежности объекта пользователю.

---

## 15. Возможный IDOR в basketItems.ts
- **Критичность:** MEDIUM
- **Категория:** N/A
- **Доказательства:**
  ```
  Semgrep (rules.idor-findone-no-owner-check): объект загружается по req.params.id без проверки владельца. Файл routes/basketItems.ts:68.
  ```
- **Рекомендация:** Проверить owner check; добавить проверку принадлежности basket item пользователю.

---

## 16. Возможный IDOR в delivery.ts
- **Критичность:** MEDIUM
- **Категория:** N/A
- **Доказательства:**
  ```
  Semgrep (rules.idor-findone-no-owner-check): объект загружается по req.params.id без проверки владельца. Файл routes/delivery.ts:34.
  ```
- **Рекомендация:** Проверить owner check; добавить проверку принадлежности delivery пользователю.

---

## 17. Потенциальный open redirect через параметр to
- **Критичность:** MEDIUM
- **Категория:** N/A
- **Доказательства:**
  ```
  const toUrl: string = query.to as string; if (security.isRedirectAllowed(toUrl)) { ... res.redirect(toUrl) }. isRedirectAllowed использует url.includes(allowedUrl) — подстроковое сравнение (lib/insecurity.ts).
  ```
- **Рекомендация:** Использовать строгий allowlist точных URL/доменов, проверять протокол и host, запрещать protocol-relative и javascript:.

---

## 18. CORS разрешает все источники
- **Критичность:** MEDIUM
- **Категория:** N/A
- **Доказательства:**
  ```
  app.options('*', cors()); app.use(cors()) — комментарий 'Bludgeon solution for possible CORS problems: Allow everything!'
  ```
- **Рекомендация:** Ограничить allowedOrigins до доверенных доменов.

---

## 19. Открытый endpoint метрик Prometheus
- **Критичность:** MEDIUM
- **Категория:** N/A
- **Доказательства:**
  ```
  serveMetrics() отдаёт register.metrics() (Content-Type: register.contentType) без проверки аутентификации; раскрывает версию, число решённых челленджей, метрики запросов.
  ```
- **Рекомендация:** Защитить endpoint аутентификацией или ограничить доступ по сети.

---

## 20. Отключён XSS-фильтр helmet
- **Критичность:** MEDIUM
- **Категория:** N/A
- **Доказательства:**
  ```
  // app.use(helmet.xssFilter()); // = no protection from persisted XSS via RESTful API
  ```
- **Рекомендация:** Включить экранирование вывода и/или настроить Content-Security-Policy.

---

## 21. Возможное раскрытие информации через документацию и CTF-материалы
- **Критичность:** LOW
- **Категория:** N/A
- **Доказательства:**
  ```
  В каталоге присутствуют SOLUTIONS.md, HALL_OF_FAME.md, threat-model.json, swagger.yml, ctf.key, config/ctf.yml, data/static/codefixes/ (решения челленджей).
  ```
- **Рекомендация:** Ограничить доступ к документации, решениям и API-спецификациям в production-окружении.

---

## 22. Небезопасная конфигурация: отключён safetyMode
- **Критичность:** LOW
- **Категория:** N/A
- **Доказательства:**
  ```
  Файл /app/juice-shop/config/unsafe.yml содержит: challenges: safetyMode: disabled
  ```
- **Рекомендация:** Проверить назначение safetyMode и активное использование unsafe.yml; включить safetyMode или ограничить доступ к конфигурации.

---

## 23. Возможная SQL-инъекция в компоненте sqli-lab
- **Критичность:** LOW
- **Категория:** N/A
- **Доказательства:**
  ```
  В выводе каталога /app указаны файлы: sqli-lab/app.py, sqli-lab/init_db.py, sqli-lab/lab_database.db, sqli-lab/templates/index.html. Содержимое не получено.
  ```
- **Рекомендация:** Проанализировать sqli-lab/app.py и init_db.py; проверить формирование SQL-запросов и использование параметризованных запросов.

---

## 24. Возможная NoSQL-инъекция в компоненте nosqli-lab
- **Критичность:** LOW
- **Категория:** N/A
- **Доказательства:**
  ```
  В выводе каталога /app указаны файлы: nosqli-lab/app.py, nosqli-lab/init_db.py, nosqli-lab/templates/index.html. Содержимое не получено.
  ```
- **Рекомендация:** Проанализировать nosqli-lab/app.py и init_db.py; проверить обработку пользовательского ввода в NoSQL-запросах.

---

## 25. Возможные LFI/RFI в компоненте target
- **Критичность:** LOW
- **Категория:** N/A
- **Доказательства:**
  ```
  В выводе каталога /app указаны файлы: target/LFI_RFI_remote.py, target/LFI_RFI_service.py, target/fi_private_page.py, target/fi_pages/welcome.py. Содержимое не получено.
  ```
- **Рекомендация:** Проанализировать target/LFI_RFI_*.py и fi_private_page.py; проверить обработку путей и разрешённые каталоги.

---

## 26. Возможный SSRF в компоненте target
- **Критичность:** LOW
- **Категория:** N/A
- **Доказательства:**
  ```
  В выводе каталога /app указаны файлы: target/SSRF_app.py, target/SSRF_service.py, target/SSRF_streamlit_app.py, target/Dockerfile.ssrf-flask. Содержимое не получено.
  ```
- **Рекомендация:** Проанализировать target/SSRF_*.py; проверить обработку URL, допустимые хосты и возможность запросов к внутренним ресурсам.

---

## 27. Возможное наличие небезопасного веб-приложения в каталоге juice-shop
- **Критичность:** LOW
- **Категория:** N/A
- **Доказательства:**
  ```
  В каталоге juice-shop: package.json, app.ts, server.ts, config/unsafe.yml, ctf.key. Приложение не запущено (connection refused на :3000).
  ```
- **Рекомендация:** Запустить приложение в изолированном стенде и выполнить DAST; проверить доступность ctf.key и config/unsafe.yml наружу.

---

## 28. Наличие security.txt (положительная находка)
- **Критичность:** LOW
- **Категория:** N/A
- **Доказательства:**
  ```
  Файл .well-known/security.txt присутствует; в server.ts настроен маршрут /.well-known/security.txt с полями contact/encryption/csaf.
  ```
- **Рекомендация:** Поддерживать актуальность security.txt (Contact, Expires).

---

## 29. Ограниченная конфигурация helmet (нет CSP)
- **Критичность:** LOW
- **Категория:** N/A
- **Доказательства:**
  ```
  app.use(helmet.noSniff()); app.use(helmet.frameguard()) — Content-Security-Policy не настроен.
  ```
- **Рекомендация:** Добавить CSP и другие заголовки helmet.

---

## 30. Ограничение: приложение не запущено, DAST невозможен
- **Критичность:** LOW
- **Категория:** N/A
- **Доказательства:**
  ```
  GET http://localhost:3000/ вернул 'Connection refused' (ERR_CONNECTION_REFUSED).
  ```
- **Рекомендация:** Запустить приложение в изолированном стенде и повторить DAST-проверки.

---

## 31. Ограничение: RAG-база знаний не проиндексирована
- **Критичность:** LOW
- **Категория:** N/A
- **Доказательства:**
  ```
  Запрос к RAG вернул: 'Ошибка: База знаний RAG еще не проиндексирована. Запустите скрипт индексации.'
  ```
- **Рекомендация:** Запустить скрипт индексации RAG и повторить запрос для обогащения отчёта.

---
