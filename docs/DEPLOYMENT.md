# Развёртывание Launchpad VPN

## 1. Сертификаты TLS

Создайте каталог `certs/` и сгенерируйте самоподписанный сертификат для тестирования:

```bash
mkdir -p certs
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout certs/server.key \
  -out certs/server.pem \
  -subj "/CN=vpn.aitelegrama.com"
```

Файл `config/server.yml` по умолчанию ожидает эти пути. Для боевого использования рекомендуется выдать сертификат через Let's Encrypt.

## 2. Настройка окружения

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python webapp/manage.py migrate
```

Администратор по умолчанию — `pasha500k` / `Hehetoto123`. При необходимости переопределите переменные окружения **до первого запуска**:

```bash
export ADMIN_USERNAME="новый-логин"
export ADMIN_PASSWORD="новый-пароль"
```

## 3. Запуск сервисов

В отдельных терминалах:

```bash
uvicorn webapp.main:app --host 0.0.0.0 --port 8000
python server/vpn_server.py
```

## 4. Создание ключей

Откройте `http://localhost:8000` — пользователи увидят лендинг с кнопкой скачивания клиента, регистрацией и активацией ключа. Для доступа в панель администратора перейдите на `/admin` и введите логин/пароль. Ключи генерируются в формате UUID и по умолчанию разрешают одну одновременную сессию.

## 5. Запуск клиента

```bash
python client/vpn_client.py \
    --server vpn.aitelegrama.com \
    --port 9443 \
    --mode domains \
    --username demo-user \
    --password secret123 \
    --domain example.com \
    --target-port 443 \
    --payload-file request.txt \
    --ca certs/server.pem
```

Для пользователей с активационным ключом замените пару `--username/--password` на `--key <UUID>` — лимиты по времени будут сняты.

Для упаковки Windows-клиента в `.exe` установите `pyinstaller` и выполните:

```bash
pyinstaller --onefile client/vpn_client.py
```

Полученный файл `dist/vpn_client.exe` можно разместить в `webapp/static/LaunchpadVPN-Setup.exe`, чтобы ссылка на сайте указывала на готовый установщик.

## 6. Ограничение доменов

- Добавьте домены в `config/domains.yml` или через веб-интерфейс.
- Перезапуск сервера или использование формы «добавить/обновить» обновит список.
- Список разрешённых доменов отправляется клиенту в режиме «Домены» в ответ на рукопожатие VMess.

## 7. Производственная эксплуатация

- Разместите веб-приложение за обратным прокси (NGINX/Traefik).
- Настройте systemd-юнит для `server/vpn_server.py` и автоматический запуск клиента обновления доменов.
- Мониторьте файл `data/vpn.db` или экспортируйте логи сессий (`vpn_sessions`) в систему аналитики, чтобы следить за квотами.
