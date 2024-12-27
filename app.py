# app.py

import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, \
                        login_user, logout_user, current_user, login_required
import bcrypt  # for password hashing

app = Flask(__name__)
app.secret_key = 'YOUR_SECRET_KEY'  # used for session management

# Path to DB file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'inventory.db')

##################################################
# DATABASE HELPERS
##################################################
def get_db_connection():
    """Create a new database connection (with row_factory)."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def create_user(username, password, role='staff'):
    """Insert a new user into the DB with a hashed password."""
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
        """, (username, password_hash, role))
        conn.commit()
    finally:
        conn.close()

def get_user_by_username(username):
    """Return user row by username, or None if not found."""
    conn = get_db_connection()
    user_row = conn.execute("""
        SELECT * FROM users WHERE username = ?
    """, (username,)).fetchone()
    conn.close()
    return user_row

##################################################
# FLASK-LOGIN SETUP
##################################################
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # route name where we log in

class User(UserMixin):
    """Flask-Login User class that wraps a DB user row."""
    def __init__(self, user_id, username, role):
        self.id = user_id        # required by Flask-Login
        self.username = username
        self.role = role

    def is_admin(self):
        return self.role == 'admin'

@login_manager.user_loader
def load_user(user_id):
    """Given a user_id, retrieve user from DB and return a User object."""
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()
    if row:
        return User(row['user_id'], row['username'], row['role'])
    return None

##################################################
# ROUTES
##################################################
@app.route('/')
def index():
    conn = get_db_connection()
    categories = conn.execute('SELECT category_name FROM categories').fetchall()
    selected_category = request.args.get('category', None)  # Set to None if no category selected
    search_query = request.args.get('search', '')
    page = int(request.args.get('page', 1))
    items_per_page = 6
    offset = (page - 1) * items_per_page

    # Query products for the selected category or all products
    if selected_category:
        products_query = '''
            SELECT p.product_id, p.product_name, p.sale_price, p.image_path
            FROM products p
            JOIN categories c ON p.category_id = c.category_id
            WHERE c.category_name = ? AND p.product_name LIKE ?
            LIMIT ? OFFSET ?
        '''
        products = conn.execute(products_query, (selected_category, f'%{search_query}%', items_per_page, offset)).fetchall()
        total_items_query = '''
            SELECT COUNT(*)
            FROM products p
            JOIN categories c ON p.category_id = c.category_id
            WHERE c.category_name = ? AND p.product_name LIKE ?
        '''
        total_items = conn.execute(total_items_query, (selected_category, f'%{search_query}%')).fetchone()[0]
        featured_products = []  # No featured products if category is selected
    else:
        products_query = '''
            SELECT p.product_id, p.product_name, p.sale_price, p.image_path
            FROM products p
            WHERE p.product_name LIKE ?
            LIMIT ? OFFSET ?
        '''
        products = conn.execute(products_query, (f'%{search_query}%', items_per_page, offset)).fetchall()
        total_items_query = '''
            SELECT COUNT(*)
            FROM products
            WHERE product_name LIKE ?
        '''
        total_items = conn.execute(total_items_query, (f'%{search_query}%',)).fetchone()[0]
        featured_products = conn.execute('''
            SELECT product_name, sale_price, image_path
            FROM products
            ORDER BY sale_price DESC
            LIMIT 3
        ''').fetchall()

    total_pages = (total_items + items_per_page - 1) // items_per_page
    conn.close()

    return render_template(
        'index.html',
        categories=categories,
        products=products,
        selected_category=selected_category,
        search_query=search_query,
        page=page,
        total_pages=total_pages,
        featured_products=featured_products
    )

@app.route('/reports/sales_transactions')
@login_required
def sales_transactions():
    """Report of all sales transactions."""
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT t.transaction_id, p.product_name, t.quantity, t.transaction_type, t.timestamp
        FROM transactions t
        JOIN products p ON t.product_id = p.product_id
        WHERE t.transaction_type = 'sale'
        ORDER BY t.timestamp DESC
    ''').fetchall()
    conn.close()

    return render_template('sales_transactions.html', transactions=rows)

@app.route('/reports/total_stock_value')
@login_required
def total_stock_value():
    """Report of total stock value."""
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT p.product_name, s.quantity, p.cost_price, (s.quantity * p.cost_price) AS total_value
        FROM products p
        JOIN stock s ON p.product_id = s.product_id
        ORDER BY total_value DESC
    ''').fetchall()
    conn.close()

    return render_template('total_stock_value.html', products=rows)

@app.route('/reports/category_stock')
@login_required
def category_stock():
    """Category-wise stock report."""
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT c.category_name, SUM(s.quantity) AS total_stock
        FROM categories c
        JOIN products p ON c.category_id = p.category_id
        JOIN stock s ON p.product_id = s.product_id
        GROUP BY c.category_name
    ''').fetchall()
    conn.close()

    return render_template('category_stock.html', rows=rows)

@app.route('/category/<category_name>')
def view_category(category_name):
    """Display products by category."""
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT p.product_name, p.sale_price, p.image_path
        FROM products p
        JOIN categories c ON p.category_id = c.category_id
        WHERE c.category_name = ?
    ''', (category_name,)).fetchall()
    conn.close()
    return render_template('category.html', category_name=category_name, products=rows)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user_row = get_user_by_username(username)
        if user_row:
            stored_hash = user_row['password_hash']  # Retrieved as a string
            if isinstance(stored_hash, str):
                stored_hash = stored_hash.encode('utf-8')  # Convert to bytes
            
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                # Create a Flask-Login user object
                user_obj = User(
                    user_id=user_row['user_id'],
                    username=user_row['username'],
                    role=user_row['role']
                )
                login_user(user_obj)
                return redirect(url_for('index'))
            else:
                flash("Invalid password.", "error")
        else:
            flash("User not found.", "error")

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")  # Add this line
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = 'user'  # Force role to 'user'

        if not username or not password:
            flash("Username and password are required.", "error")  # Add this
            return redirect(url_for('register'))

        if get_user_by_username(username) is not None:
            flash("Username already taken.", "error")  # Add this
            return redirect(url_for('register'))

        create_user(username, password, role)
        flash("Account created successfully! Please log in.", "success")  # Add this
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/place_order', methods=['POST'])
@login_required
def place_order():
    if current_user.role != 'user':
        flash("Only users can place orders.", "error")
        return redirect(url_for('index'))

    conn = get_db_connection()

    # Fetch the cart items for the user
    cart_items = conn.execute("""
        SELECT c.product_id, c.quantity, p.sale_price
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = ?
    """, (current_user.id,)).fetchall()

    if not cart_items:
        flash("Your cart is empty. Please add items to your cart before placing an order.", "error")
        return redirect(url_for('view_cart'))

    try:
        # Insert into the orders table
        cursor = conn.execute("""
            INSERT INTO orders (user_id) VALUES (?)
        """, (current_user.id,))
        order_id = cursor.lastrowid  # Get the ID of the newly created order

        # Insert into the order_products table
        for item in cart_items:
            conn.execute("""
                INSERT INTO order_products (order_id, product_id, quantity)
                VALUES (?, ?, ?)
            """, (order_id, item['product_id'], item['quantity']))

            # Update the stock in the products table
            conn.execute("""
                UPDATE stock
                SET quantity = quantity - ?
                WHERE product_id = ?
            """, (item['quantity'], item['product_id']))

        # Clear the user's cart
        conn.execute("DELETE FROM cart WHERE user_id = ?", (current_user.id,))
        conn.commit()
        flash("Order placed successfully!", "success")
    except Exception as e:
        conn.rollback()
        flash(f"An error occurred while placing your order: {str(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('order_history'))

@app.route('/add_brand', methods=['GET', 'POST'])
@login_required
def add_brand():
    if not current_user.is_admin():
        flash("Only admins can add brands.", "error")
        return redirect(url_for('index'))

    if request.method == 'POST':
        brand_name = request.form.get('brand_name')
        if not brand_name:
            flash("Brand name is required.", "error")
            return redirect(url_for('add_brand'))

        conn = get_db_connection()
        try:
            # Attempt to add the brand to the database
            conn.execute("INSERT INTO brands (brand_name) VALUES (?)", (brand_name,))
            conn.commit()
            flash("Brand added successfully!", "success")
        except sqlite3.IntegrityError:
            # Handle unique constraint errors
            flash("Brand already exists.", "error")
        finally:
            conn.close()

        return redirect(url_for('add_brand'))

    return render_template('add_brand.html')

@app.route('/view_cart')
@login_required
def view_cart():
    if current_user.role != 'user':
        flash("Only users can access the cart.", "error")
        return redirect(url_for('index'))

    conn = get_db_connection()
    conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign key constraints
    try:
        cart_items = conn.execute("""
            SELECT c.cart_id, p.product_name, p.sale_price, c.quantity
            FROM cart c
            JOIN products p ON c.product_id = p.product_id
            WHERE c.user_id = ?
        """, (current_user.id,)).fetchall()

        total_price = sum(item['sale_price'] * item['quantity'] for item in cart_items)
    except Exception as e:
        flash(f"Database error: {e}", "error")
        return redirect(url_for('index'))
    finally:
        conn.close()

    if not cart_items:
        flash("Your cart is empty.", "info")
        return redirect(url_for('index'))

    return render_template('view_cart.html', cart_items=cart_items, total_price=total_price)

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    if current_user.role != 'user':
        flash("Only users can checkout.", "error")
        return redirect(url_for('view_cart'))

    conn = get_db_connection()

    # Get all items in the user's cart
    cart_items = conn.execute("""
        SELECT c.product_id, c.quantity, p.product_name, p.sale_price, s.quantity AS stock_quantity
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        JOIN stock s ON c.product_id = s.product_id
        WHERE c.user_id = ?
    """, (current_user.id,)).fetchall()

    if not cart_items:
        flash("Your cart is empty. Add items before checking out.", "error")
        return redirect(url_for('view_cart'))

    try:
        # Insert the new order into the `orders` table
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO orders (user_id) VALUES (?)
        """, (current_user.id,))
        order_id = cursor.lastrowid

        # Insert each item into the `order_products` table and update stock
        for item in cart_items:
            if item['stock_quantity'] < item['quantity']:
                flash(f"Not enough stock for {item['product_name']}.", "error")
                return redirect(url_for('view_cart'))

            # Insert product into `order_products`
            conn.execute("""
                INSERT INTO order_products (order_id, product_id, quantity)
                VALUES (?, ?, ?)
            """, (order_id, item['product_id'], item['quantity']))

            # Update stock table
            conn.execute("""
                UPDATE stock 
                SET quantity = quantity - ?
                WHERE product_id = ?
            """, (item['quantity'], item['product_id']))

        # Clear the cart
        conn.execute("DELETE FROM cart WHERE user_id = ?", (current_user.id,))
        conn.commit()
        flash("Checkout successful! Your order has been placed.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"An error occurred during checkout: {str(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('index'))

@app.route('/admin/stock_levels')
@login_required
def stock_levels():
    if not current_user.is_admin():
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('index'))

    conn = get_db_connection()
    stock_data = conn.execute('''
        SELECT p.product_id, p.product_name, c.category_name, s.quantity
        FROM stock s
        JOIN products p ON s.product_id = p.product_id
        JOIN categories c ON p.category_id = c.category_id
        ORDER BY c.category_name, p.product_name
    ''').fetchall()
    conn.close()

    return render_template('admin/stock_levels.html', stock_data=stock_data)

@app.route('/admin/low_stock')
@login_required
def low_stock():
    if not current_user.is_admin():
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('index'))

    conn = get_db_connection()
    low_stock_data = conn.execute('''
        SELECT p.product_id, p.product_name, c.category_name, s.quantity, p.reorder_level
        FROM stock s
        JOIN products p ON s.product_id = p.product_id
        JOIN categories c ON p.category_id = c.category_id
        WHERE s.quantity < p.reorder_level
        ORDER BY c.category_name, p.product_name
    ''').fetchall()
    conn.close()

    return render_template('admin/low_stock.html', low_stock_data=low_stock_data)

@app.route('/admin/sales_report')
@login_required
def sales_report():
    if not current_user.is_admin():
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('index'))

    conn = get_db_connection()
    sales_data = conn.execute('''
        SELECT t.transaction_id, p.product_name, t.quantity, t.transaction_date
        FROM transactions t
        JOIN products p ON t.product_id = p.product_id
        WHERE t.transaction_type = 'OUT'
        ORDER BY t.transaction_date DESC
    ''').fetchall()
    conn.close()

    return render_template('admin/sales_report.html', sales_data=sales_data)

@app.route('/admin/revenue')
@login_required
def revenue_report():
    if not current_user.is_admin():
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('index'))

    conn = get_db_connection()
    revenue_data = conn.execute('''
        SELECT p.product_name, SUM(t.quantity * p.sale_price) AS total_revenue
        FROM transactions t
        JOIN products p ON t.product_id = p.product_id
        WHERE t.transaction_type = 'OUT'
        GROUP BY p.product_name
        ORDER BY total_revenue DESC
    ''').fetchall()

    total_revenue = conn.execute('''
        SELECT SUM(t.quantity * p.sale_price)
        FROM transactions t
        JOIN products p ON t.product_id = p.product_id
        WHERE t.transaction_type = 'OUT'
    ''').fetchone()[0]
    conn.close()

    return render_template('admin/revenue_report.html', revenue_data=revenue_data, total_revenue=total_revenue)

@app.route('/order_history')
@login_required
def order_history():
    if current_user.role != 'user':
        flash("Only users can view order history.", "error")
        return redirect(url_for('index'))

    conn = get_db_connection()
    orders = conn.execute("""
        SELECT 
            o.order_id, 
            o.order_date, 
            p.product_name, 
            op.quantity, 
            (op.quantity * p.sale_price) AS item_total_price
        FROM orders o
        JOIN order_products op ON o.order_id = op.order_id
        JOIN products p ON op.product_id = p.product_id
        WHERE o.user_id = ?
        ORDER BY o.order_date DESC, o.order_id
    """, (current_user.id,)).fetchall()

    # Group orders with products and calculate total price
    grouped_orders = {}
    for order in orders:
        order_id = order['order_id']
        if order_id not in grouped_orders:
            grouped_orders[order_id] = {
                'order_id': order_id,
                'date': order['order_date'],
                'products': [],
                'total_price': 0
            }
        grouped_orders[order_id]['products'].append({
            'product_name': order['product_name'],
            'quantity': order['quantity'],
            'item_total_price': order['item_total_price']
        })
        grouped_orders[order_id]['total_price'] += order['item_total_price']

    conn.close()

    return render_template('order_history.html', orders=grouped_orders.values())

@app.route('/products')
@login_required
def products():
    """Show all products and stock levels (staff-only or admin)."""
    # If you want to restrict to certain roles:
    # if not (current_user.is_admin() or current_user.role == 'staff'):
    #     flash("You do not have permission to view products.", "error")
    #     return redirect(url_for('index'))

    conn = get_db_connection()
    rows = conn.execute('''
        SELECT p.product_id, p.product_name, s.quantity
        FROM products p
        JOIN stock s ON p.product_id = s.product_id
        ORDER BY p.product_id
    ''').fetchall()
    conn.close()

    return render_template('products.html', products=rows)

@app.route('/add_to_cart', methods=['POST'])
@login_required
def add_to_cart():
    """Handle adding products to the user's cart."""
    product_id = request.form.get('product_id')
    quantity = request.form.get('quantity')

    # Validate product ID and quantity
    if not product_id or not quantity:
        flash("Product ID and quantity are required.", "error")
        return redirect(url_for('index'))

    try:
        quantity = int(quantity)
        if quantity < 1:
            flash("Quantity must be at least 1.", "error")
            return redirect(url_for('index'))
    except ValueError:
        flash("Invalid quantity.", "error")
        return redirect(url_for('index'))

    # Add to cart in the database
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO cart (user_id, product_id, quantity)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, product_id) DO UPDATE SET quantity = quantity + ?
        ''', (current_user.id, product_id, quantity, quantity))
        conn.commit()
        flash("Product added to cart successfully!", "success")
    except sqlite3.Error as e:
        flash(f"Database error: {e}", "error")
    finally:
        conn.close()

    return redirect(url_for('index'))

@app.route('/add_transaction', methods=['GET','POST'])
@login_required
def add_transaction():
    """Add an IN or OUT transaction. Admin or staff role only."""
    if request.method == 'POST':
        product_id = request.form.get('product_id')
        transaction_type = request.form.get('transaction_type')
        quantity_str = request.form.get('quantity')
        
        # Basic validation
        if not product_id or not transaction_type or not quantity_str:
            flash("All fields are required.", "error")
            return redirect(url_for('add_transaction'))
        
        try:
            quantity = int(quantity_str)
        except ValueError:
            flash("Quantity must be a number.", "error")
            return redirect(url_for('add_transaction'))

        # Insert transaction with parameterized query
        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT INTO transactions (product_id, transaction_type, quantity)
                VALUES (?, ?, ?)
            ''', (product_id, transaction_type, quantity))
            conn.commit()
        except sqlite3.IntegrityError as e:
            flash(f"Error adding transaction: {e}", "error")
            conn.close()
            return redirect(url_for('add_transaction'))
        
        conn.close()
        flash("Transaction added successfully!", "success")
        return redirect(url_for('products'))

    else:
        # GET request -> Show form
        conn = get_db_connection()
        product_rows = conn.execute("SELECT product_id, product_name FROM products").fetchall()
        conn.close()
        return render_template('add_transaction.html', products=product_rows)

@app.route('/reports')
@login_required
def reports():
    """Reports page with links."""
    return render_template('reports.html')

if __name__ == '__main__':
    app.run(debug=True)