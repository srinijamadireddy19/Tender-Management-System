from flask import Flask, render_template, request, redirect, url_for, flash, session
from tenderhub.models import db, User, Vendor, Tender, Bid
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import abort
from datetime import datetime
from flask_migrate import Migrate
from flask import session

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://admin:tenderhub123@tenderhub.cf04w0ce4nv3.us-east-1.rds.amazonaws.com/tenderhub'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable track modifications for performance
app.config['SECRET_KEY'] = 'secret'
db.init_app(app)
migrate = Migrate(app, db)

with app.app_context():
    db.create_all()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':  # Check if the user has 'admin' role
            abort(403)  # Return a 403 Forbidden response if not an admin
        return f(*args, **kwargs)
    return decorated_function

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('You need to be logged in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        phone = request.form.get('phone')

        # Hash the password before storing it
        hashed_password = generate_password_hash(password)

        # Check if the user already exists
        user_exists = User.query.filter((User.username == username) | (User.email == email)).first()
        if user_exists:
            flash('Username or Email already exists!', 'danger')
            return redirect(url_for('register'))

        # Create the new user with the default role as 'user'
        new_user = User(username=username, password=hashed_password, email=email,
                        first_name=first_name, last_name=last_name, phone=phone, role='user')
        db.session.add(new_user)
        db.session.commit()
        flash('You are successfully registered! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user'] = user.username
            session['user_id'] = user.id
            session['user_role'] = user.role
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials, please try again.', 'danger')

    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out!', 'info')
    return redirect(url_for('login'))

# Home route
@app.route('/')
def home():
    if 'user' in session:
        return render_template('home.html', user=session['user'])
    return redirect(url_for('login'))

# Vendors route (for admin)
@app.route('/vendor')
@login_required
def vendor():
    if session.get('user_role') != 'admin':
        abort(403)
    vendors = Vendor.query.all()
    return render_template('vendor.html', vendors=vendors)

# Create Vendor route (for admin)
@app.route('/create_vendor', methods=['GET', 'POST'])
@login_required
def create_vendor():
    if session.get('user_role') != 'admin':
        abort(403)
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        phone = request.form['phone']
        addr = request.form['addr']
        new_vendor = Vendor(first_name=first_name, last_name=last_name, email=email, phone=phone, addr=addr)
        db.session.add(new_vendor)
        db.session.commit()
        flash('Vendor created successfully!', 'success')
        return redirect(url_for('vendor'))
    return render_template('create_vendor.html')

@app.route('/vendor/<int:vendor_id>', methods=['GET'])
@login_required
def view_vendor(vendor_id):
    # Check if user is admin
    if session.get('user_role') != 'admin':
        abort(403)
    
    # Retrieve the vendor details by vendor_id
    vendor = Vendor.query.get_or_404(vendor_id)
    
    # Pass the vendor details to the template
    return render_template('view_vendor.html', vendor=vendor)

@app.route('/vendor/<int:vendor_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_vendor(vendor_id):
    if session.get('user_role') != 'admin':
        abort(403)

    # Get the vendor by ID or return a 404 error if not found
    vendor = Vendor.query.get_or_404(vendor_id)
    
    if request.method == 'POST':
        # Update vendor details
        vendor.first_name = request.form['first_name']
        vendor.last_name = request.form['last_name']
        vendor.email = request.form['email']
        vendor.phone = request.form['phone']
        vendor.addr = request.form['addr']
        db.session.commit()

        flash('Vendor details updated successfully!', 'success')
        return redirect(url_for('view_vendor', vendor_id=vendor.id))

    # Render the edit form with the current vendor details
    return render_template('edit_vendor.html', vendor=vendor)

@app.route('/vendor/<int:vendor_id>/delete', methods=['POST'])
@login_required
def delete_vendor(vendor_id):
    if session.get('user_role') != 'admin':
        abort(403)
    
    # Get the vendor by ID or return a 404 error if not found
    vendor = Vendor.query.get_or_404(vendor_id)
    
    db.session.delete(vendor)
    db.session.commit()
    
    flash('Vendor deleted successfully!', 'success')
    return redirect(url_for('vendor'))


# Tenders route (for admin)
@app.route('/tender')
@login_required
def tender():
    tenders = Tender.query.all()
    return render_template('tender.html', tenders=tenders)

# Create Tender route (for admin)
@app.route('/create_tender', methods=['GET', 'POST'])
@login_required
def create_tender():
    if session.get('user_role') != 'admin':
        abort(403)
    if request.method == 'POST':
        title = request.form['title']
        type = request.form['type']
        price = request.form['price']
        description = request.form['description']
        deadline = request.form['deadline']
        new_tender = Tender(title=title,type=type,price=price, description=description, deadline=datetime.strptime(deadline, '%Y-%m-%d'))
        db.session.add(new_tender)
        db.session.commit()
        flash('Tender created successfully!', 'success')
        return redirect(url_for('tender'))
    return render_template('create_tender.html')

@app.route('/tender/<int:tender_id>', methods=['GET'])
@login_required
def view_tender(tender_id):
    # Retrieve the tender with related vendor and bids
    tender = Tender.query.get_or_404(tender_id)
    vendor = Vendor.query.get(tender.vendor_id)  # Fetch the vendor for this tender

    # Retrieve bids for the tender
    bids = Bid.query.filter_by(tender_id=tender_id).all()
    
    return render_template('view_tender.html', tender=tender, vendor=vendor, bids=bids)



@app.route('/tender/<int:tender_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_tender(tender_id):
    if session.get('user_role') != 'admin':
        abort(403)

    # Get the tender by ID or return a 404 error if not found
    tender = Tender.query.get_or_404(tender_id)
    
    if request.method == 'POST':
        # Update tender details
        tender.title = request.form['title']
        tender.description = request.form['description']
        tender.deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d')
        db.session.commit()

        flash('Tender details updated successfully!', 'success')
        return redirect(url_for('view_tender', tender_id=tender.id))

    # Render the edit form with the current tender details
    return render_template('edit_tender.html', tender=tender)

@app.route('/tender/<int:tender_id>/delete', methods=['POST'])
@login_required
def delete_tender(tender_id):
    if session.get('user_role') != 'admin':
        abort(403)

    tender = Tender.query.get_or_404(tender_id)
    db.session.delete(tender)
    db.session.commit()
    flash('Tender deleted successfully!', 'success')
    return redirect(url_for('tender'))


# View Bids (for vendors)
@app.route('/bids')
@login_required
def bids():
    if session.get('user_role') != 'admin':
        abort(403)
    vendor = Vendor.query.filter_by(email=session['user']).first()
    bids = Bid.query.filter_by(vendor_id=vendor.id).all()
    return render_template('bids.html', bids=bids)

@app.route('/my_bids')
@login_required
def my_bids():
    user_id = session.get('user_id')  # Assuming user_id is stored in session after login
    bids = Bid.query.filter_by(user_id=user_id).all()  # Retrieve all bids placed by the user
    return render_template('my_bids.html', bids=bids)

@app.route('/update_bid/<int:bid_id>', methods=['POST'])
@admin_required
def update_bid(bid_id):
    bid = Bid.query.get(bid_id)
    bid.status = request.form['status']  # Get status from a form input
    db.session.commit()
    flash('Bid status updated successfully.')
    return redirect(url_for('admin_dashboard'))  # Redirect to the admin dashboard


@app.route('/tender/<int:tender_id>/place_bid', methods=['GET', 'POST'])
@login_required
def place_bid(tender_id):
    # Check if the user is not admin
    if session.get('user_role') == 'admin':
        abort(403)  # Admins should not place bids

    # Retrieve the tender by tender_id
    tender = Tender.query.get_or_404(tender_id)

    if request.method == 'POST':
        # Get bid details from form
        bid_amount = request.form['bid_amount']
        
        # Assuming user_id is stored in session
        user_id = session.get('user_id')  # Retrieve user_id from the session

        # Create new bid entry using the session-stored user_id
        new_bid = Bid(tender_id=tender_id, user_id=user_id, amount=bid_amount)
        db.session.add(new_bid)
        db.session.commit()

        flash('Bid placed successfully!', 'success')
        return redirect(url_for('tender'))

    return render_template('place_bid.html', tender=tender)


@app.route('/bid/<int:bid_id>/accept', methods=['POST'])
@login_required
def accept_bid(bid_id):
    if session.get('user_role') != 'admin':
        abort(403)

    bid = Bid.query.get_or_404(bid_id)
    bid.status = 'accepted'
    db.session.commit()
    flash('Bid accepted successfully!', 'success')
    return redirect(url_for('view_tender', tender_id=bid.tender_id))

@app.route('/bid/<int:bid_id>/reject', methods=['POST'])
@login_required
def reject_bid(bid_id):
    if session.get('user_role') != 'admin':
        abort(403)

    bid = Bid.query.get_or_404(bid_id)
    bid.status = 'rejected'
    db.session.commit()
    flash('Bid rejected successfully!', 'danger')
    return redirect(url_for('view_tender', tender_id=bid.tender_id))



if __name__ == '__main__':
    app.run(debug=True)