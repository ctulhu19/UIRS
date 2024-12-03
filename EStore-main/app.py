from flask import Flask, jsonify, render_template, request, redirect, url_for, flash,session, abort
from flask_sqlalchemy import SQLAlchemy
from PIL import Image 
import settings 
import os
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import xml.etree.ElementTree as ET

app = Flask(__name__)

app.config['SECRET_KEY'] = settings.SECRET_KEY 
app.config['SQLALCHEMY_DATABASE_URI'] = settings.DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = settings.TRACK_MODIFICATIONS
app.config['UPLOAD_FOLDER'] = settings.UPLOAD_FOLDER
db = SQLAlchemy(app)
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_filename = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    quantity = db.Column(db.Integer, nullable=False)
    is_hidden = db.Column(db.Boolean, default=False)
    is_archived = db.Column(db.Boolean, default=False)  # Новое поле
    def __repr__(self):
        return f'<Product {self.name}>'
    
class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    product = db.relationship('Product', backref=db.backref('cart_items', lazy=True))
    user = db.relationship('User', backref=db.backref('cart_items', lazy=True))
    def __repr__(self):
        return f'<CartItem {self.product.name} for user {self.user.username}>'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    last_name = db.Column(db.String(30), nullable=True)  
    first_name = db.Column(db.String(30), nullable=True)
    patronymic = db.Column(db.String(30), nullable=True) 
    postal_code = db.Column(db.String(6), nullable=True) 
    region =db.Column(db.String(30), nullable=True)  
    city = db.Column(db.String(30), nullable=True)  
    street = db.Column(db.String(30), nullable=True) 
    house = db.Column(db.String(30), nullable=True) 
    apartment = db.Column(db.String(30), nullable=True) 
    phone = db.Column(db.String(15), nullable=True)  
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    def __repr__(self):
        return f'<User {self.username}>'

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    order_time = db.Column(db.DateTime, default=datetime.utcnow)
    last_name = db.Column(db.String(30), nullable=False)
    first_name = db.Column(db.String(30), nullable=False)
    patronymic = db.Column(db.String(30), nullable=True)
    postal_code = db.Column(db.String(6), nullable=True)
    region = db.Column(db.String(30), nullable=True)
    city = db.Column(db.String(30), nullable=True)
    street = db.Column(db.String(30), nullable=True)
    house = db.Column(db.String(30), nullable=True)
    apartment = db.Column(db.String(30), nullable=True)
    phone = db.Column(db.String(15), nullable=True)
    user = db.relationship('User', backref=db.backref('orders', lazy=True))
    product = db.relationship('Product', backref=db.backref('orders', lazy=True))
    def __repr__(self):
        return f'<Order {self.id} for User {self.user_id}>'
    
class ActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('action_logs', lazy=True))
    def __repr__(self):
        return f'<ActionLog {self.id} - User {self.user_id}: {self.action} at {self.timestamp}>'

with app.app_context():
    db.create_all()

def log_action(user_id, action):
    # Получаем пользователя по user_id
    user = User.query.get(user_id)
    username = user.username if user else 'Unknown User'  # Если пользователь не найден

    # Логируем действие в базе данных
    log_entry = ActionLog(user_id=user_id, action=action)
    db.session.add(log_entry)
    db.session.commit()
    log_file_path_txt = 'action_logs.txt'
    log_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    with open(log_file_path_txt, 'a', encoding='utf-8') as log_file:
        log_file.write(f'{log_time} - User {username}: {action}\n')
    log_file_path_json = 'action_logs.json'
    log_entry_data = {
        'timestamp': log_time,
        'user_id': user_id,
        'username': username,
        'action': action
    }
    try:
        with open(log_file_path_json, 'a', encoding='utf-8') as log_file:
            log_file.write(json.dumps(log_entry_data, ensure_ascii=False) + '\n')
    except Exception as e:
        print(f"Ошибка записи в JSON файл: {e}")
    log_file_path_xml = 'action_logs.xml'
    log_entry_element = ET.Element("log_entry")
    ET.SubElement(log_entry_element, "timestamp").text = log_time
    ET.SubElement(log_entry_element, "user_id").text = str(user_id)
    ET.SubElement(log_entry_element, "username").text = username
    ET.SubElement(log_entry_element, "action").text = action
    try:
        if not os.path.exists(log_file_path_xml):
            root = ET.Element("action_logs")
            root.append(log_entry_element)
            tree = ET.ElementTree(root)
            tree.write(log_file_path_xml, encoding='utf-8', xml_declaration=True)
        else:
            tree = ET.parse(log_file_path_xml)
            root = tree.getroot()
            root.append(log_entry_element)
            tree.write(log_file_path_xml, encoding='utf-8')
    except Exception as e:
        print(f"Ошибка записи в XML файл: {e}")

login_manager = LoginManager(app)
login_manager.login_view = 'login'
# Загрузка пользователя по его id
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('store/shop/index.html')

@app.route('/shop')
def shop():
    # Логируем действия пользователя, если он авторизован
    if current_user.is_authenticated:
        log_action(current_user.id, 'Пользователь перешел на страницу магазина')
    
    query = request.args.get('q', '')
    sort = request.args.get('sort', 'name_asc')

    # Фильтрация только видимых товаров
    products = Product.query.filter_by(is_hidden=False, is_archived=False)
    
    if query:
        products = products.filter(Product.name.contains(query))

    # Сортировка
    if sort == 'name_asc':
        products = products.order_by(Product.name.asc())
        if current_user.is_authenticated:
            log_action(current_user.id, 'Пользователь отсортировал товары по возрастанию названия')
        else: 
            log_action(1, 'Неизвестный отсортировал товары по возрастанию названия')
    elif sort == 'name_desc':
        products = products.order_by(Product.name.desc())
        if current_user.is_authenticated:
            log_action(current_user.id, 'Пользователь отсортировал товары по убыванию названия')
    elif sort == 'price_asc':
        products = products.order_by(Product.price.asc())
        if current_user.is_authenticated:
            log_action(current_user.id, 'Пользователь отсортировал товары по возрастанию цены')
    elif sort == 'price_desc':
        products = products.order_by(Product.price.desc())
        if current_user.is_authenticated:
            log_action(current_user.id, 'Пользователь отсортировал товары по убыванию цены')

    products = products.all()

    return render_template('store/shop/shop.html', products=products, query=query, sort=sort)

@app.route('/product/<int:id>')
def product_detail(id):
    product = Product.query.get_or_404(id)
    if current_user.is_authenticated:
        log_action(current_user.id, f'Перешел на страницу товара: {product.name}')
    else: 
        log_action(1, f'YНеизвестный Перешел на страницу товара: {product.name}')
    if product.is_hidden == False and product.is_archived == False:
        recent_products = Product.query.filter(Product.id != id, Product.is_hidden == False,Product.is_archived == False).order_by(Product.id.desc()).limit(5).all()
        return render_template('store/shop/product_detail.html', product=product, recent_products=recent_products)
    else:
        return redirect(url_for('shop'))

@app.route('/shop/user/<int:user_id>', methods=['GET'], endpoint='shop.user_profile')
@login_required
def user_profile(user_id):
    # Логика для отображения профиля пользователя
    user = User.query.get_or_404(user_id)
    if current_user.id != user_id:
        log_action(current_user.id, f'Хотел перейти на страницу чужого пользователя - {user_id}')
        abort(403)  # Запретить доступ к чужим профилям
    # Извлекаем заказы из базы данных для данного пользователя
    orders = Order.query.filter_by(user_id=user_id).all()
    log_action(current_user.id, f'Пользователь зашел на свою страницу')
    return render_template('store/user/user_profile.html', user=user, orders = orders)

@app.route('/adminproduct', methods=['GET', 'POST'])
@login_required
def adminproduct():
    if not current_user.is_admin:
        flash('У вас нет прав для доступа к этой странице.', 'danger')
        log_action(current_user.id, f'Пользователь хотел воспользоваться управлением товарами')
        return redirect(url_for('login'))
    
    query = request.args.get('q', '')
    sort = request.args.get('sort', 'name_asc')
    visibility = request.args.get('visibility', 'all')

    # Получаем все товары для отображения
    products = Product.query.filter(Product.is_archived == False)

    # Фильтрация по видимости
    if visibility == 'visible':
        products = products.filter_by(is_hidden=False)
    elif visibility == 'hidden':
        products = products.filter_by(is_hidden=True)

    # Фильтрация по запросу
    if query:
        products = products.filter(Product.name.contains(query))

    # Сортировка
    if sort == 'name_asc':
        products = products.order_by(Product.name.asc())
    elif sort == 'name_desc':
        products = products.order_by(Product.name.desc())
    elif sort == 'price_asc':
        products = products.order_by(Product.price.asc())
    elif sort == 'price_desc':
        products = products.order_by(Product.price.desc())

    products = products.all()

    return render_template('admin/product/show_product.html', products=products, query=query, sort=sort, visibility=visibility)

@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        price = float(request.form['price'])
        description = request.form['description']
        quantity = int(request.form['quantity'])  # Добавляем обработку количества
        image = request.files['image']
        
        if image:
            image_filename = image.filename
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            
            # Открываем изображение и изменяем его размер
            img = Image.open(image)
            img = img.resize((600, 600)) 
            img.save(image_path)  
            
            # Добавляем товар в базу данных
            new_product = Product(name=name, price=price, description=description, image_filename=image_filename, quantity=quantity)
            db.session.add(new_product)
            db.session.commit()
            
            return redirect(url_for('add_product'))
    return render_template('admin/product/add_product.html')

@app.route('/adminproduct/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_product(id):
    if not current_user.is_admin:
        flash('У вас нет прав для доступа к этой странице.', 'danger')
        log_action(current_user.id, 'Пользователь хотел изменить товар')
        return redirect(url_for('login'))
    
    product = Product.query.get_or_404(id)

    if request.method == 'POST':
        product.name = request.form['name']
        product.description = request.form['description']
        product.price = float(request.form['price'])
        product.quantity = int(request.form['quantity'])

        image = request.files.get('image')
        if image:
            image_filename = image.filename
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            img = Image.open(image)
            img = img.resize((600, 600))
            img.save(image_path)
            product.image_filename = image_filename
        
        db.session.commit()
        
        return redirect(url_for('adminproduct'))

    return render_template('admin/product/edit_product.html', product=product)


@app.route('/adminproduct/delete/<int:id>', methods=['POST'])
@login_required
def delete_product(id):
    if not current_user.is_admin:
        flash('У вас нет прав для доступа к этой странице.', 'danger')
        log_action(current_user.id, f'Пользователь хотел удалить товар')
        return redirect(url_for('login'))
    
    product = Product.query.get_or_404(id)
    product.is_archived = True  # Устанавливаем флаг is_archived
    db.session.commit()
    return redirect(url_for('adminproduct'))


@app.route('/adminproduct/toggle/<int:id>', methods=['POST'])
@login_required
def toggle_visibility(id):
    if not current_user.is_admin:
        flash('У вас нет прав для доступа к этой странице.', 'danger')
        return redirect(url_for('login'))
    product = Product.query.get_or_404(id)
    product.is_hidden = not product.is_hidden  # Меняем статус видимости товара
    db.session.commit()
    return redirect(url_for('adminproduct'))

@app.route('/secret-admin-login', methods=['GET', 'POST'])
def secret_admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password) and user.is_admin:
            login_user(user)
            return redirect(url_for('admin'))  # Перенаправляем на страницу админки
        else:
            flash('Неправильный логин или пароль', 'danger')

    return render_template('admin/auth/admin_login.html')  # Шаблон для админского логина

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password) and not user.is_admin:
            login_user(user)
            log_action(current_user.id, f'Пользователь авторизовался')
            return redirect(url_for('shop'))
        else:
            flash('Неправильный логин или пароль', 'danger')

    return render_template('store/auth/login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        last_name = request.form.get('last_name', '')  # Фамилия
        first_name = request.form.get('first_name', '')
        patronymic = request.form.get('patronymic','')  # Имя
        postal_code = request.form.get('postal_code', '')  # Почтовый индекс
        region = request.form.get('region', '')  # Регион
        city = request.form.get('city', '')  # Город
        street = request.form.get('street', '')  # Улица
        house = request.form.get('house', '')  # Номер дома
        apartment = request.form.get('apartment', '')  # Номер квартиры
        phone = request.form.get('phone', '')  # Телефон

        # Проверка, существует ли уже пользователь с таким именем
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Пользователь с таким именем уже существует.', 'danger')
            return redirect(url_for('register'))

        # Создаем нового пользователя
        new_user = User(
            username=username,
            last_name=last_name,
            first_name=first_name,
            postal_code=postal_code,
            region=region,
            city=city,
            street=street,
            house=house,
            apartment=apartment,
            phone=phone,
            patronymic=patronymic
        )
        new_user.set_password(password)  # Хешируем пароль
        db.session.add(new_user)  # Добавляем пользователя в сессию
        db.session.commit()  # Сохраняем изменения в базе данных
        
        flash('Регистрация прошла успешно! Вы можете войти.', 'success')

        return redirect(url_for('login'))

    return render_template('store/auth/register.html')  # Возвращаем страницу регистрации

@app.route('/logout')
@login_required
def logout():
    log_action(current_user.id, f'Пользователь вышел из системы')
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('login'))

@app.route('/add_to_cart/<int:id>', methods=['POST'])
@login_required
def add_to_cart(id):
    product = Product.query.get_or_404(id)
    quantity_to_add = int(request.form.get('quantity', 1))

    # Логируем добавление товара в корзину
    if current_user.is_authenticated:
        log_action(current_user.id, f'Пользователь добавил товар в корзину - ID: {product.id}, Название: {product.name}, Количество: {quantity_to_add}')

    # Проверяем, существует ли уже этот товар в корзине пользователя
    cart_item = CartItem.query.filter_by(user_id=current_user.id, product_id=product.id).first()

    if cart_item:
        # Увеличиваем количество товара в корзине
        total_quantity = cart_item.quantity + quantity_to_add
        if current_user.is_authenticated:
            log_action(current_user.id, f'Пользователь изменил количество товара в корзине - ID: {product.id}, Название: {product.name}, Новое количество: {total_quantity}')
        
        if total_quantity > product.quantity:
            cart_item.quantity = product.quantity
            if current_user.is_authenticated:
                log_action(current_user.id, f'Количество товара в корзине ограничено до доступного - ID: {product.id}, Название: {product.name}, Количество: {product.quantity}')
        else:
            cart_item.quantity = total_quantity
    else:
        # Создаем новый элемент корзины
        if quantity_to_add > product.quantity:
            quantity_to_add = product.quantity
            if current_user.is_authenticated:
                log_action(current_user.id, f'Количество товара ограничено до доступного - ID: {product.id}, Название: {product.name}, Количество: {quantity_to_add}')
        cart_item = CartItem(user_id=current_user.id, product_id=product.id, quantity=quantity_to_add)
        db.session.add(cart_item)

    db.session.commit()
    return redirect(url_for('view_cart'))

@app.route('/update_cart_quantity', methods=['POST'])
def update_cart_quantity():
    product_id = request.form.get('id')
    new_quantity = int(request.form.get('quantity'))

    # Найдите товар в корзине
    cart = session.get('cart', [])
    for item in cart:
        if item['id'] == int(product_id):
            item['quantity'] = min(new_quantity, item['max_quantity'])  # Ограничение по максимальному количеству товара
            break
    
    session['cart'] = cart

    # Рассчитайте новую общую стоимость
    total_price = sum(item['quantity'] * item['price'] for item in cart)
    return jsonify({'total_price': total_price, 'cart_count': len(cart)})

@app.route('/cart', methods=['GET'])
@login_required
def view_cart():
    # Получаем все товары в корзине для текущего пользователя
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    if current_user.is_authenticated:
        log_action(current_user.id, f' Пользователь зашел  корзину')
    for item in cart_items:
        product = Product.query.get(item.product_id)
        if product and product.is_hidden or product.is_archived:
            CartItem.query.filter_by(user_id=current_user.id, product_id=product.id).delete()

    db.session.commit()
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total_price = sum(item.product.price * item.quantity for item in cart_items)
    user = User.query.filter_by(id=current_user.id).first()
    recommended_products = Product.query.filter(
        Product.id.notin_([item.product_id for item in cart_items]), 
        Product.is_hidden == False,
        Product.is_archived == False
    ).order_by(db.func.random()).limit(3).all()
    return render_template('store/user/cart.html', cart_items=cart_items, total_price=total_price, recommended_products=recommended_products, user=user)

@app.route('/remove_from_cart/<int:id>', methods=['POST'])
@login_required
def remove_from_cart(id):
    cart_item = CartItem.query.filter_by(id=id, user_id=current_user.id).first()
    if cart_item:
        db.session.delete(cart_item)
        db.session.commit()
        if current_user.is_authenticated:
            log_action(current_user.id, f' Пользователь удалил товар из корзины')
    else:
        pass
    return redirect(url_for('view_cart'))


@app.route('/about')
def about():
    if current_user.is_authenticated:
        log_action(current_user.id, f' Пользователь зашел на страницу о магазине')
    return render_template('store/shop/about.html')

@app.route('/admin')
def admin():
    if not current_user.is_admin:
        flash('У вас нет прав для доступа к этой странице.', 'danger')
        if current_user.is_authenticated:
            log_action(current_user.id, f' Пользователь попытался зайти на панель админа')
        return redirect(url_for('login'))
    return render_template('admin/panel/admin.html')

@app.route('/process_order', methods=['POST'])
def process_order():
    try:
        user_id = current_user.id
        if user_id is None:
            return redirect(url_for('login'))
        user_info = {
            'last_name': request.form.get('last_name'),
            'first_name': request.form.get('first_name'),
            'patronymic': request.form.get('patronymic'),
            'postal_code': request.form.get('postal_code'),
            'region': request.form.get('region'),
            'city': request.form.get('city'),
            'street': request.form.get('street'),
            'house': request.form.get('house'),
            'apartment': request.form.get('apartment'),
            'phone': request.form.get('phone')
        }
        user = User.query.get(user_id)
        if user:
            user.last_name = user_info['last_name']
            user.first_name = user_info['first_name']
            user.patronymic = user_info['patronymic']
            user.postal_code = user_info['postal_code']
            user.region = user_info['region']
            user.city = user_info['city']
            user.street = user_info['street']
            user.house = user_info['house']
            user.apartment = user_info['apartment']
            user.phone = user_info['phone']
            db.session.commit() 

        # Получаем корзину из базы данных для текущего пользователя
        cart_items = CartItem.query.filter_by(user_id=user_id).all()

        # Проверка наличия товаров на складе
        for item in cart_items:
            product = Product.query.get(item.product_id)
            if product and product.quantity < item.quantity:
                return redirect(url_for('view_cart'))

        # Обновляем количество товаров и сохраняем изменения в БД
        for item in cart_items:
            product = Product.query.get(item.product_id)
            if product:
                product.quantity -= item.quantity  

                if product.quantity == 0:
                    product.is_hidden = True

                # Добавляем заказ с информацией о доставке
                order = Order(
                    user_id=user_id,
                    product_id=item.product_id,
                    quantity=item.quantity,
                    last_name=user_info['last_name'],
                    first_name=user_info['first_name'],
                    patronymic=user_info['patronymic'],
                    postal_code=user_info['postal_code'],
                    region=user_info['region'],
                    city=user_info['city'],
                    street=user_info['street'],
                    house=user_info['house'],
                    apartment=user_info['apartment'],
                    phone=user_info['phone']
                )
                db.session.add(order)

        db.session.commit()

        # Очистка корзины в базе данных после успешного оформления заказа
        CartItem.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        if current_user.is_authenticated:
            log_action(current_user.id, f' Пользователь оформил заказ')

    except Exception as e:
        print(e)
        if current_user.is_authenticated:
            log_action(current_user.id, f' При оформлении заказа возникла ошибка {e}')
        return redirect(url_for('view_cart'))
        

    return redirect(url_for('view_cart'))

@app.route('/view_orders')
@login_required
def view_orders():
    if not current_user.is_admin:
        log_action(current_user.id, f' Пользователь попытался зайти на просмотр всех заказов пользователей')
        return redirect(url_for('login'))

    # Извлекаем все заказы и сортируем по дате заказа (новые сверху)
    orders = Order.query.order_by(Order.order_time.desc()).all()

    return render_template('/admin/view/view_orders.html', orders=orders)

@app.route('/view_logs')
@login_required
def view_logs():
    if not current_user.is_admin:
        flash('У вас нет прав для доступа к этой странице.', 'danger')
        log_action(current_user.id, f' Пользователь попытался зайти на просмотр действий всех пользователей')
        return redirect(url_for('login'))

    logs = ActionLog.query.order_by(ActionLog.timestamp.desc()).all()
    return render_template('admin/view/view_logs.html', logs=logs)

if __name__ == "__main__":
    app.run(debug=True)
    