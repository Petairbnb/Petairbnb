import os
import enum
from datetime import datetime, timedelta
import logging

from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from werkzeug.utils import secure_filename
import stripe
import paypalrestsdk
from dotenv import load_dotenv
from geopy.geocoders import Nominatim
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from authlib.integrations.flask_client import OAuth
from redis import Redis
from opencensus.ext.azure.log_exporter import AzureLogHandler

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.addHandler(AzureLogHandler(
    connection_string=os.environ.get('APPLICATIONINSIGHTS_CONNECTION_STRING')
))

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"postgresql://{os.getenv('POSTGRES_USER')}:{os.getenv('POSTGRES_PASSWORD')}"
    f"@{os.getenv('POSTGRES_HOST')}:{os.getenv('POSTGRES_PORT')}/{os.getenv('POSTGRES_DB')}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.config['REDIS_URL'] = f"redis://{os.getenv('REDIS_HOST')}:{os.getenv('REDIS_PORT')}"
app.config['WEBSITE_HOSTNAME'] = os.environ.get('WEBSITE_HOSTNAME')

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
limiter = Limiter(app, key_func=get_remote_address)
oauth = OAuth(app)

# Initialize Redis
redis_client = Redis.from_url(app.config['REDIS_URL'])

# Payment setup
stripe.api_key = os.getenv("STRIPE_API_KEY")
paypalrestsdk.configure({
    "mode": os.getenv("PAYPAL_MODE", "sandbox"),
    "client_id": os.getenv("PAYPAL_CLIENT_ID"),
    "client_secret": os.getenv("PAYPAL_CLIENT_SECRET")
})

# Social login setup
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

oauth.register(
    name='microsoft',
    server_metadata_url='https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

oauth.register(
    name='apple',
    server_metadata_url='https://appleid.apple.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email name'}
)

# Geolocation setup
geolocator = Nominatim(user_agent="dogbnb")

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Enums
class ServiceType(enum.Enum):
    SITTER = "sitter"
    GROOMER = "groomer"
    WALKER = "walker"

class TransportOption(enum.Enum):
    DROP_OFF = "drop_off"
    PICK_UP = "pick_up"
    NONE = "none"

class PaymentMethod(enum.Enum):
    STRIPE = "stripe"
    PAYPAL = "paypal"

class VerificationStatus(enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    is_service_provider = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    refresh_token = db.Column(db.String(250), nullable=True)
    social_id = db.Column(db.String(250), nullable=True)
    social_provider = db.Column(db.String(250), nullable=True)

class ServiceProvider(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    address = db.Column(db.String(250), nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    service_type = db.Column(db.Enum(ServiceType))
    price_per_hour = db.Column(db.Float)
    price_per_day = db.Column(db.Float)
    price_per_week = db.Column(db.Float)
    is_available = db.Column(db.Boolean, default=True)
    offers_pickup = db.Column(db.Boolean, default=False)
    pickup_fee = db.Column(db.Float, default=0)
    id_image = db.Column(db.LargeBinary)
    profile_pic = db.Column(db.LargeBinary)
    verification_status = db.Column(db.Enum(VerificationStatus), default=VerificationStatus.PENDING)

    user = db.relationship('User', backref=db.backref('service_provider', uselist=False))

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dog_owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('service_provider.id'), nullable=False)
    service_type = db.Column(db.Enum(ServiceType))
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    transport_option = db.Column(db.Enum(TransportOption))
    payment_method = db.Column(db.Enum(PaymentMethod))
    payment_status = db.Column(db.String(20), default="pending")

    dog_owner = db.relationship('User', foreign_keys=[dog_owner_id])
    provider = db.relationship('ServiceProvider', foreign_keys=[provider_id])

# Utility functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def calculate_price(provider, start_time, end_time, transport_option):
    duration = end_time - start_time
    days, seconds = duration.days, duration.seconds
    hours = seconds // 3600

    weeks = days // 7
    remaining_days = days % 7

    price = (
        weeks * provider.price_per_week +
        remaining_days * provider.price_per_day +
        hours * provider.price_per_hour
    )

    if transport_option == TransportOption.PICK_UP and provider.offers_pickup:
        price += provider.pickup_fee

    return price

def process_payment(amount, payment_method):
    try:
        if payment_method == PaymentMethod.STRIPE:
            stripe.Charge.create(
                amount=int(amount * 100),  # Stripe uses cents
                currency="usd",
                source="tok_visa",  # Replace with actual token from frontend
                description="Dog service payment"
            )
        elif payment_method == PaymentMethod.PAYPAL:
            payment = paypalrestsdk.Payment({
                "intent": "sale",
                "payer": {"payment_method": "paypal"},
                "transactions": [{
                    "amount": {
                        "total": str(amount),
                        "currency": "USD"
                    },
                    "description": "Dog service payment"
                }]
            })
            if not payment.create():
                raise Exception(payment.error)
        return True
    except Exception as e:
        logger.error(f"Payment processing failed: {str(e)}")
        return False

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        is_service_provider = 'is_service_provider' in request.form
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, password=hashed_password, is_service_provider=is_service_provider)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember_me = 'remember_me' in request.form
        
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.id)
            refresh_token = create_refresh_token(identity=user.id) if remember_me else None
            if refresh_token:
                user.refresh_token = refresh_token
                db.session.commit()
            
            flash('Logged in successfully', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Please check your email and password.', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard')
@jwt_required()
def dashboard():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if user.is_service_provider:
        provider = ServiceProvider.query.filter_by(user_id=current_user_id).first()
        return render_template('provider_dashboard.html', user=user, provider=provider)
    else:
        bookings = Booking.query.filter_by(dog_owner_id=current_user_id).all()
        return render_template('user_dashboard.html', user=user, bookings=bookings)

@app.route('/become-provider', methods=['GET', 'POST'])
@jwt_required()
def become_provider():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if request.method == 'POST':
        if not user.is_service_provider:
            return jsonify({"error": "User is not a service provider"}), 403
        
        name = request.form['name']
        address = request.form['address']
        service_type = request.form['service_type']
        price_per_hour = float(request.form['price_per_hour'])
        price_per_day = float(request.form['price_per_day'])
        price_per_week = float(request.form['price_per_week'])
        offers_pickup = 'offers_pickup' in request.form
        pickup_fee = float(request.form.get('pickup_fee', 0))
        id_image = request.files['id_image']
        profile_pic = request.files['profile_pic']
        
        location = geolocator.geocode(address)
        if not location:
            flash('Invalid address', 'danger')
            return redirect(url_for('become_provider'))
        
        new_provider = ServiceProvider(
            user_id=current_user_id,
            name=name,
            address=address,
            latitude=location.latitude,
            longitude=location.longitude,
            service_type=ServiceType[service_type],
            price_per_hour=price_per_hour,
            price_per_day=price_per_day,
            price_per_week=price_per_week,
            offers_pickup=offers_pickup,
            pickup_fee=pickup_fee,
            id_image=id_image.read(),
            profile_pic=profile_pic.read()
        )
        db.session.add(new_provider)
        db.session.commit()
        
        flash('Provider profile created successfully', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('become_provider.html')

@app.route('/providers')
def list_providers():
    service_type = request.args.get('service_type')
    query = ServiceProvider.query
    if service_type:
        query = query.filter_by(service_type=ServiceType[service_type])
    providers = query.all()
    return render_template('list_providers.html', providers=providers)

@app.route('/book/<int:provider_id>', methods=['GET', 'POST'])
@jwt_required()
@limiter.limit("5 per minute")
def book_provider(provider_id):
    current_user_id = get_jwt_identity()
    provider = ServiceProvider.query.get(provider_id)
    
    if request.method == 'POST':
        if not provider:
            flash('ServiceProvider not found', 'danger')
            return redirect(url_for('list_providers'))
        if not provider.is_available:
            flash('ServiceProvider is not available', 'danger')
            return redirect(url_for('list_providers'))
        
        start_time = datetime.fromisoformat(request.form['start_time'])
        end_time = datetime.fromisoformat(request.form['end_time'])
        transport_option = TransportOption[request.form['transport_option']]
        payment_method = PaymentMethod[request.form['payment_method']]
        
        total_price = calculate_price(provider, start_time, end_time, transport_option)
        
        if not process_payment(total_price, payment_method):
            flash('Payment failed', 'danger')
            return redirect(url_for('book_provider', provider_id=provider_id))
        
        new_booking = Booking(
            dog_owner_id=current_user_id,
            provider_id=provider_id,
            service_type=provider.service_type,
            start_time=start_time,
            end_time=end_time,
            total_price=total_price,
            transport_option=transport_option,
            payment_method=payment_method,
            payment_status="completed"
        )
        db.session.add(new_booking)
        db.session.commit
      db.session.add(new_booking)
        db.session.commit()
        
        flash('Booking created successfully', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('book_provider.html', provider=provider)

@app.route('/logout')
@jwt_required()
def logout():
    # Here you would typically invalidate the JWT token
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# Health check endpoint for Azure
@app.route('/healthz')
def health_check():
    return jsonify({"status": "healthy"}), 200

# Azure-specific startup tasks
@app.before_first_request
def azure_startup_tasks():
    # Ensure all database tables are created
    db.create_all()
    
    # You can add more startup tasks here if needed
    # For example, creating an admin user if it doesn't exist
    admin_email = os.getenv('ADMIN_EMAIL')
    if admin_email and not User.query.filter_by(email=admin_email).first():
        admin_password = os.getenv('ADMIN_PASSWORD')
        hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
        admin_user = User(email=admin_email, password=hashed_password, is_admin=True)
        db.session.add(admin_user)
        db.session.commit()

# Custom CLI commands
@app.cli.command("init-db")
def init_db_command():
    """Clear existing data and create new tables."""
    db.drop_all()
    db.create_all()
    print("Initialized the database.")

if __name__ == '__main__':
    # Use this for local development
    app.run(host='0.0.0.0', port=8000)
else:
    # Use this for production with Gunicorn
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
