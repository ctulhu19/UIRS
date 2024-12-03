# EStore

## Чтобы все заработало, нужно установить библиотеки, выполните следующие команды в терминале
```
python3 -m venv .venv
source ./.venv/bin/activate
pip install -r requirements.txt
```

## Дальше чтобы войти в админскую панель, вам нужно зарегистрировать админа, для этого нужно вести в терминал команды 
```
flask shell
```
и в нее ввести следующие команды
```
from app import db
from app import User  # Импортируйте вашу модель User
# Создайте нового администратора
admin = User(username='admin')  # Замените 'admin' на желаемое имя пользователя
admin.set_password('root')  # Установите пароль для администратора
admin.is_admin = True  # Установите флаг is_admin в True

# Добавьте нового пользователя в базу данных и сохраните изменения
db.session.add(admin)
db.session.commit()

```
