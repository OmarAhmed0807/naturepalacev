from datetime import datetime, date
from decimal import Decimal
from functools import wraps
import os
import secrets
from flask import Flask, render_template, redirect, url_for, flash, request, abort, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db = SQLAlchemy(app)
login_manager = LoginManager(app); login_manager.login_view = 'login'; login_manager.login_message = 'Please log in to continue.'

class User(UserMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True); username=db.Column(db.String(80), unique=True, nullable=False); password_hash=db.Column(db.String(255), nullable=False); role=db.Column(db.String(30), default='admin'); active=db.Column(db.Boolean, default=True); created_at=db.Column(db.DateTime, default=datetime.utcnow)
    def set_password(self,p): self.password_hash=generate_password_hash(p)
    def check_password(self,p): return check_password_hash(self.password_hash,p)
class Category(db.Model):
    id=db.Column(db.Integer, primary_key=True); name=db.Column(db.String(120), unique=True, nullable=False); description=db.Column(db.Text); image=db.Column(db.String(255)); created_at=db.Column(db.DateTime, default=datetime.utcnow)
    products=db.relationship('Product', backref='category', lazy=True)
class Customer(db.Model):
    id=db.Column(db.Integer, primary_key=True); name=db.Column(db.String(160), nullable=False); phone=db.Column(db.String(50)); email=db.Column(db.String(160)); address=db.Column(db.Text); notes=db.Column(db.Text); created_at=db.Column(db.DateTime, default=datetime.utcnow)
    sales=db.relationship('Sale', backref='customer', lazy=True)
class Product(db.Model):
    id=db.Column(db.Integer, primary_key=True); name=db.Column(db.String(180), nullable=False); sku=db.Column(db.String(80), unique=True, nullable=False); description=db.Column(db.Text); purchase_price=db.Column(db.Numeric(12,2), default=0); selling_price=db.Column(db.Numeric(12,2), default=0); supplier=db.Column(db.String(160)); min_stock=db.Column(db.Integer, default=0); image=db.Column(db.String(255)); is_serialized=db.Column(db.Boolean, default=False); stock_quantity=db.Column(db.Integer, default=0); created_at=db.Column(db.DateTime, default=datetime.utcnow); category_id=db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    serials=db.relationship('SerialNumber', backref='product', lazy=True, cascade='all, delete-orphan')
class SerialNumber(db.Model):
    id=db.Column(db.Integer, primary_key=True); serial=db.Column(db.String(160), unique=True, nullable=False, index=True); status=db.Column(db.String(20), default='available', nullable=False); product_id=db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False); sold_sale_item_id=db.Column(db.Integer, db.ForeignKey('sale_items.id')); created_at=db.Column(db.DateTime, default=datetime.utcnow)
class StockMovement(db.Model):
    id=db.Column(db.Integer, primary_key=True); product_id=db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False); quantity=db.Column(db.Integer, nullable=False); movement_type=db.Column(db.String(30), nullable=False); serial_number=db.Column(db.String(160)); user_id=db.Column(db.Integer, db.ForeignKey('user.id')); notes=db.Column(db.Text); created_at=db.Column(db.DateTime, default=datetime.utcnow)
    product=db.relationship('Product'); user=db.relationship('User')
class Sale(db.Model):
    id=db.Column(db.Integer, primary_key=True); invoice_no=db.Column(db.String(50), unique=True, nullable=False, index=True); customer_id=db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False); total_amount=db.Column(db.Numeric(12,2), default=0); created_by=db.Column(db.Integer, db.ForeignKey('user.id')); created_at=db.Column(db.DateTime, default=datetime.utcnow)
    items=db.relationship('SaleItem', backref='sale', lazy=True, cascade='all, delete-orphan')
    user=db.relationship('User')
class SaleItem(db.Model):
    __tablename__='sale_items'; id=db.Column(db.Integer, primary_key=True); sale_id=db.Column(db.Integer, db.ForeignKey('sale.id'), nullable=False); product_id=db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False); quantity=db.Column(db.Integer, nullable=False); unit_price=db.Column(db.Numeric(12,2), nullable=False); serial_number=db.Column(db.String(160)); product=db.relationship('Product')


@app.before_request
def csrf_protect():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    if request.method == 'POST' and request.endpoint != 'login':
        token = request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            abort(400, description='Invalid CSRF token.')

@app.context_processor
def csrf_context():
    return {'csrf_token': session.get('csrf_token')}

@login_manager.user_loader
def load_user(uid): return db.session.get(User,int(uid))

def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a,**kw):
        if current_user.role!='admin': abort(403)
        return f(*a,**kw)
    return w

def save_image(file):
    if not file or not file.filename: return None
    allowed={'png','jpg','jpeg','webp','gif'}
    ext=file.filename.rsplit('.',1)[-1].lower() if '.' in file.filename else ''
    if ext not in allowed: return None
    name=f"{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{secure_filename(file.filename)}"; file.save(os.path.join(app.config['UPLOAD_FOLDER'],name)); return name

def next_invoice(): return f"NP-{datetime.utcnow().strftime('%Y%m%d')}-{Sale.query.count()+1:05d}"

@app.context_processor
def inject(): return {'today':date.today()}
@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method=='POST':
        u=User.query.filter_by(username=request.form.get('username','').strip()).first()
        if u and u.active and u.check_password(request.form.get('password','')):
            login_user(u, remember=False); return redirect(url_for('dashboard'))
        flash('Invalid username or password.','danger')
    return render_template('login.html')
@app.get('/logout')
@login_required
def logout(): logout_user(); return redirect(url_for('login'))

@app.get('/')
@login_required
def dashboard():
    products=Product.query.count(); categories=Category.query.count(); customers=Customer.query.count(); sales=Sale.query.order_by(Sale.created_at.desc()).limit(8).all(); low=Product.query.filter(Product.stock_quantity<=Product.min_stock).order_by(Product.stock_quantity.asc()).limit(8).all(); total_stock=db.session.query(db.func.coalesce(db.func.sum(Product.stock_quantity),0)).scalar() or 0; revenue=db.session.query(db.func.coalesce(db.func.sum(Sale.total_amount),0)).scalar() or 0
    return render_template('dashboard.html', products=products,categories=categories,customers=customers,sales=sales,low=low,total_stock=total_stock,revenue=revenue)

@app.route('/users', methods=['GET','POST'])
@admin_required
def users():
    if request.method == 'POST':
        try:
            username = request.form.get('username','').strip()
            password = request.form.get('password','')
            role = request.form.get('role','staff')
            if not username or not password:
                raise ValueError('Username and password are required.')
            if role not in ('admin','staff'):
                raise ValueError('Invalid role.')
            if User.query.filter_by(username=username).first():
                raise ValueError('Username already exists.')
            u = User(username=username, role=role, active=True)
            u.set_password(password)
            db.session.add(u); db.session.commit()
            flash('User created successfully.','success')
        except Exception as e:
            db.session.rollback(); flash(str(e),'danger')
        return redirect(url_for('users'))
    return render_template('users.html', users=User.query.order_by(User.username).all())

@app.route('/users/<int:id>/edit', methods=['GET','POST'])
@admin_required
def user_edit(id):
    u = db.session.get(User,id) or abort(404)
    if request.method == 'POST':
        try:
            username = request.form.get('username','').strip()
            role = request.form.get('role','staff')
            if not username: raise ValueError('Username is required.')
            if role not in ('admin','staff'): raise ValueError('Invalid role.')
            other = User.query.filter(User.username == username, User.id != u.id).first()
            if other: raise ValueError('Username already exists.')
            if u.id == current_user.id and (not u.active or role != 'admin'):
                raise ValueError('You cannot remove admin access or deactivate your own account.')
            u.username = username; u.role = role; u.active = request.form.get('active') == 'on'
            new_password = request.form.get('password','')
            if new_password: u.set_password(new_password)
            db.session.commit(); flash('User updated successfully.','success')
        except Exception as e:
            db.session.rollback(); flash(str(e),'danger')
        return redirect(url_for('users'))
    return render_template('user_edit.html', user=u)

@app.post('/users/<int:id>/delete')
@admin_required
def user_delete(id):
    u = db.session.get(User,id) or abort(404)
    if u.id == current_user.id:
        flash('You cannot delete your own account.','danger')
    elif u.username == 'omar':
        flash('The main admin account cannot be deleted.','danger')
    else:
        u.active = False
        db.session.commit()
        flash('User deactivated.','success')
    return redirect(url_for('users'))

@app.route('/categories', methods=['GET','POST'])
@admin_required
def categories():
    if request.method=='POST':
        name=request.form.get('name','').strip()
        if not name: flash('Category name is required.','danger')
        elif Category.query.filter_by(name=name).first(): flash('Category already exists.','danger')
        else:
            c=Category(name=name,description=request.form.get('description'),image=save_image(request.files.get('image'))); db.session.add(c); db.session.commit(); flash('Category created.','success')
        return redirect(url_for('categories'))
    return render_template('categories.html', categories=Category.query.order_by(Category.name).all())
@app.post('/categories/<int:id>/delete')
@admin_required
def category_delete(id):
    c=db.session.get(Category,id) or abort(404)
    if c.products: flash('Cannot delete a category that still contains products.','danger')
    else: db.session.delete(c); db.session.commit(); flash('Category deleted.','success')
    return redirect(url_for('categories'))

@app.route('/products', methods=['GET','POST'])
@admin_required
def products():
    if request.method=='POST':
        try:
            sku=request.form.get('sku','').strip(); name=request.form.get('name','').strip(); cat=int(request.form['category_id']); serialized=request.form.get('is_serialized')=='on'; qty=int(request.form.get('quantity') or 0)
            if not sku or not name: raise ValueError('Name and SKU are required.')
            if Product.query.filter_by(sku=sku).first(): raise ValueError('SKU already exists.')
            if qty<0: raise ValueError('Quantity cannot be negative.')
            p=Product(name=name,sku=sku,category_id=cat,description=request.form.get('description'),purchase_price=Decimal(request.form.get('purchase_price') or 0),selling_price=Decimal(request.form.get('selling_price') or 0),supplier=request.form.get('supplier'),min_stock=int(request.form.get('min_stock') or 0),is_serialized=serialized,image=save_image(request.files.get('image')),stock_quantity=0)
            db.session.add(p); db.session.flush()
            if serialized:
                raw=[x.strip() for x in request.form.get('serial_numbers','').splitlines() if x.strip()]
                if len(raw)!=len(set(raw)): raise ValueError('Duplicate serial numbers were entered.')
                for s in raw:
                    if SerialNumber.query.filter_by(serial=s).first(): raise ValueError(f'Serial number {s} already exists.')
                    db.session.add(SerialNumber(serial=s,product_id=p.id)); db.session.add(StockMovement(product_id=p.id,quantity=1,movement_type='in',serial_number=s,user_id=current_user.id,notes='Initial stock'))
                p.stock_quantity=len(raw)
            else:
                p.stock_quantity=qty
                if qty: db.session.add(StockMovement(product_id=p.id,quantity=qty,movement_type='in',user_id=current_user.id,notes='Initial stock'))
            db.session.commit(); flash('Product created.','success')
        except Exception as e: db.session.rollback(); flash(str(e),'danger')
        return redirect(url_for('products'))
    q=request.args.get('q','').strip(); category_id=request.args.get('category_id','')
    query=Product.query
    if q: query=query.filter(db.or_(Product.name.ilike(f'%{q}%'),Product.sku.ilike(f'%{q}%'),Product.serials.any(SerialNumber.serial.ilike(f'%{q}%'))))
    if category_id: query=query.filter_by(category_id=int(category_id))
    return render_template('products.html', products=query.order_by(Product.name).all(),categories=Category.query.order_by(Category.name).all(),q=q,category_id=category_id)
@app.post('/products/<int:id>/delete')
@admin_required
def product_delete(id):
    p=db.session.get(Product,id) or abort(404)
    if SaleItem.query.filter_by(product_id=id).first(): flash('Product has sales history and cannot be permanently deleted.','danger')
    else: db.session.delete(p); db.session.commit(); flash('Product deleted.','success')
    return redirect(url_for('products'))
@app.get('/products/<int:id>')
@login_required
def product_detail(id):
    p=db.session.get(Product,id) or abort(404); movements=StockMovement.query.filter_by(product_id=id).order_by(StockMovement.created_at.desc()).limit(100).all(); return render_template('product_detail.html',p=p,movements=movements)

@app.route('/inventory', methods=['GET','POST'])
@admin_required
def inventory():
    if request.method=='POST':
        try:
            p=db.session.get(Product,int(request.form['product_id'])) or abort(404); typ=request.form['type']; qty=int(request.form.get('quantity') or 0); notes=request.form.get('notes')
            if p.is_serialized:
                serials=[x.strip() for x in request.form.get('serial_numbers','').splitlines() if x.strip()]
                if typ=='in':
                    for s in serials:
                        if SerialNumber.query.filter_by(serial=s).first(): raise ValueError(f'Serial {s} already exists.')
                        db.session.add(SerialNumber(serial=s,product_id=p.id,status='available')); db.session.add(StockMovement(product_id=p.id,quantity=1,movement_type='in',serial_number=s,user_id=current_user.id,notes=notes))
                    p.stock_quantity += len(serials)
                elif typ in ('out','adjust'):
                    available=[s for s in serials if (sn:=SerialNumber.query.filter_by(serial=s,product_id=p.id,status='available').first())]
                    if len(available)!=len(serials): raise ValueError('One or more serials are invalid or unavailable.')
                    for s in available:
                        sn.status='removed'; db.session.add(StockMovement(product_id=p.id,quantity=-1,movement_type=typ,serial_number=s,user_id=current_user.id,notes=notes))
                    p.stock_quantity -= len(available)
            else:
                if qty<0: raise ValueError('Quantity cannot be negative.')
                delta=qty if typ=='in' else -qty if typ=='out' else qty-p.stock_quantity
                if p.stock_quantity+delta<0: raise ValueError('Stock cannot become negative.')
                p.stock_quantity += delta; db.session.add(StockMovement(product_id=p.id,quantity=delta,movement_type=typ, user_id=current_user.id,notes=notes))
            db.session.commit(); flash('Inventory updated.','success')
        except Exception as e: db.session.rollback(); flash(str(e),'danger')
        return redirect(url_for('inventory'))
    q=request.args.get('q',''); products=Product.query.filter(db.or_(Product.name.ilike(f'%{q}%'),Product.sku.ilike(f'%{q}%'))).order_by(Product.name).all() if q else Product.query.order_by(Product.name).all(); movements=StockMovement.query.order_by(StockMovement.created_at.desc()).limit(100).all(); return render_template('inventory.html',products=products,movements=movements,q=q)

@app.route('/customers', methods=['GET','POST'])
@login_required
def customers():
    if request.method=='POST':
        name=request.form.get('name','').strip()
        if not name: flash('Customer name is required.','danger')
        else: db.session.add(Customer(name=name,phone=request.form.get('phone'),email=request.form.get('email'),address=request.form.get('address'),notes=request.form.get('notes'))); db.session.commit(); flash('Customer created.','success')
        return redirect(url_for('customers'))
    q=request.args.get('q',''); cs=Customer.query.filter(db.or_(Customer.name.ilike(f'%{q}%'),Customer.phone.ilike(f'%{q}%'),Customer.email.ilike(f'%{q}%'))).order_by(Customer.name).all() if q else Customer.query.order_by(Customer.name).all(); return render_template('customers.html',customers=cs,q=q)
@app.get('/customers/<int:id>')
@login_required
def customer_detail(id):
    c=db.session.get(Customer,id) or abort(404); return render_template('customer_detail.html',c=c)

@app.route('/sales/new', methods=['GET','POST'])
@login_required
def new_sale():
    if request.method=='POST':
        try:
            customer=db.session.get(Customer,int(request.form['customer_id'])) or abort(404); raw=request.form.get('items_json','[]'); import json; items=json.loads(raw)
            if not items: raise ValueError('Add at least one product.')
            sale=Sale(invoice_no=next_invoice(),customer_id=customer.id,created_by=current_user.id,total_amount=0); db.session.add(sale); db.session.flush(); total=Decimal('0')
            for it in items:
                p=db.session.get(Product,int(it['product_id'])) or abort(404); price=Decimal(str(p.selling_price)); qty=int(it.get('quantity',1)); serial=(it.get('serial_number') or '').strip() or None
                if p.stock_quantity < 0: raise ValueError(f'Invalid stock state for {p.name}.')
                if p.is_serialized:
                    if not serial: raise ValueError(f'Select a serial number for {p.name}.')
                    if any(x is not it and int(x.get('product_id',0)) == p.id and (x.get('serial_number') or '').strip() == serial for x in items):
                        raise ValueError(f'Serial {serial} was added more than once.')
                    sn=SerialNumber.query.filter_by(product_id=p.id,serial=serial,status='available').first()
                    if not sn: raise ValueError(f'Serial {serial} is unavailable.')
                    qty=1; si=SaleItem(sale_id=sale.id,product_id=p.id,quantity=1,unit_price=price,serial_number=serial); db.session.add(si); db.session.flush(); sn.status='sold'; sn.sold_sale_item_id=si.id; p.stock_quantity-=1; db.session.add(StockMovement(product_id=p.id,quantity=-1,movement_type='sale',serial_number=serial,user_id=current_user.id,notes=sale.invoice_no))
                else:
                    if qty<=0: raise ValueError('Quantity must be positive.')
                    if p.stock_quantity<qty: raise ValueError(f'Insufficient stock for {p.name}.')
                    db.session.add(SaleItem(sale_id=sale.id,product_id=p.id,quantity=qty,unit_price=price)); p.stock_quantity-=qty; db.session.add(StockMovement(product_id=p.id,quantity=-qty,movement_type='sale',user_id=current_user.id,notes=sale.invoice_no))
                total += price*qty
            sale.total_amount=total; db.session.commit(); flash(f'Sale {sale.invoice_no} created.','success'); return redirect(url_for('sale_detail',id=sale.id))
        except Exception as e: db.session.rollback(); flash(str(e),'danger')
    return render_template('new_sale.html',customers=Customer.query.order_by(Customer.name).all(),products=Product.query.order_by(Product.name).all())
@app.get('/sales')
@login_required
def sales():
    q=request.args.get('q',''); query=Sale.query.join(Customer)
    if q: query=query.filter(db.or_(Sale.invoice_no.ilike(f'%{q}%'),Customer.name.ilike(f'%{q}%'),Customer.phone.ilike(f'%{q}%')))
    return render_template('sales.html',sales=query.order_by(Sale.created_at.desc()).all(),q=q)
@app.get('/sales/<int:id>')
@login_required
def sale_detail(id): return render_template('sale_detail.html',sale=db.session.get(Sale,id) or abort(404))

@app.get('/api/products/<int:id>/serials')
@login_required
def api_serials(id): return jsonify([{'serial':s.serial,'status':s.status} for s in SerialNumber.query.filter_by(product_id=id,status='available').order_by(SerialNumber.serial).all()])
@app.get('/search')
@login_required
def global_search():
    q=request.args.get('q','').strip(); products=Product.query.filter(db.or_(Product.name.ilike(f'%{q}%'),Product.sku.ilike(f'%{q}%'),Product.serials.any(SerialNumber.serial.ilike(f'%{q}%')))).limit(20).all() if q else []; customers=Customer.query.filter(db.or_(Customer.name.ilike(f'%{q}%'),Customer.phone.ilike(f'%{q}%'))).limit(20).all() if q else []; sales=Sale.query.filter(Sale.invoice_no.ilike(f'%{q}%')).limit(20).all() if q else []; return render_template('search.html',q=q,products=products,customers=customers,sales=sales)

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='omar').first():
        u=User(username='omar',role='admin'); u.set_password('Omar@0807'); db.session.add(u); db.session.commit()

if __name__=='__main__': app.run(debug=os.getenv('FLASK_DEBUG','0')=='1')
