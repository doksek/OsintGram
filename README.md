<p align="center"><img src="docs/logo.png" width="160" alt="OsintGram"></p>

# OsintGram

Неофициальный Telegram-клиент для Android с инструментами OSINT — для журналистов, фактчекеров и тех, кто разбирает скам.
Основан на [Forkgram](https://github.com/Forkgram/TelegramAndroid), который в свою очередь основан на [официальном Telegram для Android](https://github.com/DrKLO/Telegram).

> OsintGram не связан с Telegram FZ-LLC. Все данные обрабатываются локально на телефоне, приложение не отправляет ничего сторонним серверам — только серверам Telegram, как обычный клиент.

## Функции OSINT

Долгое нажатие на любое сообщение → в меню появляются пункты:

**OSINT: сообщение** — отчёт по сообщению:
- ID сообщения, чата, публичная ссылка на сообщение (`t.me/...`);
- точное время отправки и редактирования в UTC, просмотры, пересылки, подпись автора;
- «паспорт» отправителя: ID, юзернеймы (включая неактивные), дата-центр по фото профиля, метки бот / verified / premium / **SCAM** / **FAKE**;
- откуда переслано: исходный канал или пользователь, ID и ссылка на оригинальный пост, дата оригинала;
- медиа: имя файла, MIME, размер, ID файла и дата-центр;
- найденные в тексте индикаторы: ссылки (включая скрытые за текстом), @упоминания, e-mail, крипто-кошельки BTC / ETH (EVM) / TRON / TON;
- SHA-256 текста сообщения.

Кнопки: **Копировать** и **Сохранить доказательство** — в `Загрузки/OsintGram/` сохраняются `.json` (машиночитаемый) и `.txt` (для людей) с отметкой времени фиксации и SHA-256 файла.

**OSINT: индикаторы чата** — собирает ссылки, упоминания, e-mail и кошельки из загруженных сообщений чата в таблицу `.csv` (`Загрузки/OsintGram/`): тип, значение, сколько раз встречается, первое сообщение и ссылка на него. Прокрутите чат вверх, чтобы подгрузить больше истории.

Чего OsintGram намеренно **не делает**: скрытое отслеживание онлайна конкретных людей, поиск по утёкшим базам, массовый сбор телефонов участников групп.

## Установка

1. Откройте раздел [Releases](../../releases/latest).
2. Скачайте `OsintGram.apk`.
3. Установите на телефон (разрешите установку из неизвестных источников).

OsintGram ставится рядом с обычным Telegram и не заменяет его.

## Сборка своей версии

Сборка идёт в GitHub Actions, компьютер не нужен.

1. Сделайте форк репозитория.
2. Получите `api_id` и `api_hash` на [my.telegram.org](https://my.telegram.org) → API development tools.
3. В форке: **Settings → Secrets and variables → Actions** → добавьте секреты `APP_ID` и `APP_HASH`.
4. **Actions → OsintGram APK → Run workflow**.

Необязательно — свой ключ подписи (чтобы обновления ставились поверх): секреты `KEYSTORE_BASE64` (keystore в base64), `KEYSTORE_PASS`, `KEY_ALIAS`, `KEY_PASS`. Без них APK подписывается тестовым ключом.

Код OSINT-функций: [`TMessagesProj/src/main/java/org/telegram/messenger/osint/OsintTools.java`](TMessagesProj/src/main/java/org/telegram/messenger/osint/OsintTools.java).

## Лицензия

GPL-2.0, как у Telegram для Android и Forkgram. Спасибо авторам [Forkgram](https://github.com/Forkgram/TelegramAndroid) и [Telegram](https://github.com/DrKLO/Telegram).
