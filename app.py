# --- Rental Space Management System - app.py ---
# This is a complete, corrected, and refactored version of the application.

# --- Core Imports ---
import os
import random
import string
from datetime import date, timedelta, datetime
import calendar
from functools import wraps
from sqlalchemy.exc import NoResultFound
from thefuzz import fuzz
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from sqlalchemy import MetaData
import tablib
import io

# --- Flask and Extension Imports ---
from flask import (Flask, flash, jsonify, redirect,
                   render_template, request, url_for)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import joinedload, subqueryload
from sqlalchemy import event
from sqlalchemy import func, and_
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)


class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'admin'

    def inaccessible_callback(self, name, **kwargs):
        # Redirect non-admins to the login page
        return redirect(url_for('login', next=request.url))


# --- Application Setup ---
app = Flask(__name__)
app.secret_key = os.environ.get(
    'SECRET_KEY', 'a-default-secret-key-for-development')
# 1. Get the absolute path of the directory where this file (app.py) is located.
basedir = os.path.abspath(os.path.dirname(__file__))

# 2. Define the path for the instance folder.
instance_path = os.path.join(basedir, 'instance')

# 3. Ensure the instance folder exists. Flask does not create it automatically.
os.makedirs(instance_path, exist_ok=True)

# 4. Construct the absolute path to the database file.
db_path = os.path.join(instance_path, 'rsms.db')

# 5. Set the database URI using the absolute path.
# The three slashes are important for SQLite to correctly interpret the absolute path.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', f'sqlite:///{db_path}')

# The rest of your configuration remains the same
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

naming_convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

db = SQLAlchemy(app, metadata=MetaData(naming_convention=naming_convention))
admin = Admin(app, name='RSMS Admin', template_mode='bootstrap4')

migrate = Migrate(app, db, render_as_batch=True)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# --- Database Models ---
user_location_association = db.Table('user_location',
                                     db.Column('user_id', db.Integer, db.ForeignKey(
                                         'user.id'), primary_key=True),
                                     db.Column('location_id', db.Integer, db.ForeignKey(
                                         'location.id'), primary_key=True)
                                     )


class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False, unique=True)
    spaces = db.relationship('Space', backref='location',
                             cascade="all, delete-orphan", lazy=True)


class Space(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey(
        'location.id'), nullable=False)
    bookings = db.relationship(
        'Booking', back_populates='space', lazy='dynamic', cascade="all, delete-orphan")


class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    code = db.Column(db.String(128), unique=True, nullable=False)
    bookings = db.relationship(
        'Booking', back_populates='client', lazy=True, cascade="all, delete-orphan")


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    booking_number = db.Column(db.String(10), unique=True, nullable=False)
    space_id = db.Column(db.Integer, db.ForeignKey('space.id'), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey(
        'client.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    rental_fee = db.Column(db.Float, nullable=False)
    notes = db.Column(db.Text)

    # Relationships
    space = db.relationship('Space', back_populates='bookings')
    # --- THIS IS THE LINE THAT FIXES THE ERROR ---
    client = db.relationship('Client', back_populates='bookings')

    @property
    def total_booking_days(self):
        """Calculates the total number of days for the booking, inclusive."""
        if self.start_date and self.end_date:
            # Add 1 because the time delta is exclusive of the end day
            return (self.end_date - self.start_date).days + 1
        return 0


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    locations = db.relationship(
        'Location', secondary=user_location_association, backref='users', lazy='subquery')

    def set_password(
        self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(
        self.password_hash, password)


class BookingAuditLog(db.Model):
    __tablename__ = 'booking_audit_log'
    id = db.Column(db.Integer, primary_key=True)
    # Ensure booking_number is unique and indexed
    booking_number = db.Column(db.String(10), nullable=True)
    # Make booking_id nullable and add the ondelete='SET NULL' rule
    booking_id = db.Column(db.Integer, db.ForeignKey(
        'booking.id', ondelete='SET NULL'), nullable=True, index=True)

    user_id = db.Column(db.Integer, db.ForeignKey(
        'user.id'), nullable=False, index=True)
    action = db.Column(db.String(20), nullable=False, index=True)
    timestamp = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    details = db.Column(db.Text, nullable=True)

    # Ensure no cascade options are in the backref
    booking = db.relationship(
        'Booking', backref=db.backref('audit_logs', lazy=True))

    user = db.relationship('User', backref='booking_audit_logs')


class BookingSequence(db.Model):
    # This table will only ever have one row with id=1
    id = db.Column(db.Integer, primary_key=True)
    next_value = db.Column(db.Integer, nullable=False, default=1)


class BookingAdminView(AdminModelView):
    # All configurations must be indented inside the class block.

    can_export = True

    column_export_list = [
        'booking_number',
        'space.location.name',
        'space.name',
        'client.name',
        'start_date',
        'end_date',
        'rental_fee',
        'notes'
    ]

    # The 'form_args' dictionary should also be inside the class.
    form_args = {
        'booking_number': {
            'label': 'Booking ID',
            'flags': {'readonly': True}
        }
    }

    # All other column configurations must also be indented.
    column_list = ['booking_number', 'space', 'client',
                   'start_date', 'end_date', 'rental_fee']

    column_searchable_list = ['booking_number', 'client.name']

    column_filters = ['space.location.name', 'start_date', 'end_date']


class UserAdminView(AdminModelView):
    # Hide the password hash from the list and forms for security
    column_exclude_list = ['password_hash']
    form_excluded_columns = ['password_hash']


# --- Add Views for Your Models ---
# Add each of your models to the admin interface, using the custom views where needed.

# For User, we use the custom view to hide the password
admin.add_view(UserAdminView(User, db.session, name='App Users'))

# For Client, Location, and Space, the default secure view is fine
admin.add_view(AdminModelView(Client, db.session, name='Vendors'))
admin.add_view(AdminModelView(Location, db.session))
admin.add_view(AdminModelView(Space, db.session))

# --- THIS IS THE CRITICAL FIX ---
# We must explicitly tell Flask-Admin to use our new BookingAdminView for the Booking model.
admin.add_view(BookingAdminView(Booking, db.session))


# --- Helper Functions ---


def get_next_booking_number():
    """
    Safely retrieves and increments the next booking number from the sequence.
    If the sequence is not initialized, it creates it automatically and safely.
    This function is concurrency-safe to prevent race conditions.
    """
    while True:
        try:
            with db.session.begin_nested():
                # Attempt to lock the sequence row for update.
                # .one_or_none() is safer than .one() as it returns None if not found.
                sequence = BookingSequence.query.filter_by(
                    id=1).with_for_update().one_or_none()

                # --- Auto-Initialization Logic ---
                if sequence is None:
                    # If the sequence does not exist, create it.
                    # This code will only run once in the application's lifetime.
                    sequence = BookingSequence(id=1, next_value=1)
                    db.session.add(sequence)
                    # The 'begin_nested' block will commit this new row.
                    print("INFO: Booking sequence auto-initialized.")

                next_number = sequence.next_value
                sequence.next_value += 1

            # If the transaction was successful, break the loop and return the number.
            return f"{next_number:06d}"

        except IntegrityError:
            # This handles a rare race condition where two processes try to create
            # the initial sequence at the exact same time. One will succeed, the
            # other will get an IntegrityError. This 'except' block catches it,
            # rolls back, and the `while True` loop makes it try again, succeeding
            # on the second attempt.
            db.session.rollback()
            print("WARNING: Race condition during sequence initialization. Retrying.")
            continue


def calculate_prorated_fee(booking, start_date, end_date):
    overlap_start = max(booking.start_date, start_date)
    overlap_end = min(booking.end_date, end_date)
    if overlap_start > overlap_end:
        return 0.0, 0
    overlap_days = (overlap_end - overlap_start).days + 1
    total_days = booking.total_booking_days
    return (round((booking.rental_fee / total_days) * overlap_days, 2), overlap_days) if total_days > 0 else (0.0, 0)


def group_dates_into_ranges(dates):
    if not dates:
        return []
    s_dates = sorted(list(dates))
    ranges, start = [], s_dates[0]
    for i in range(1, len(s_dates)):
        if (s_dates[i] - s_dates[i-1]).days > 1:
            ranges.append((start, s_dates[i-1]))
            start = s_dates[i]
    ranges.append((start, s_dates[-1]))
    return ranges


def format_date_range(start, end):
    return start.strftime('%d-%m-%Y') if start == end else f"{start.strftime('%d-%m-%Y')} to {end.strftime('%d-%m-%Y')}"


def get_base_location_query():
    """Centralized function to get a SQLAlchemy query for locations based on user role."""
    if current_user.role == 'admin':
        return Location.query
    else:
        user_location_ids = [loc.id for loc in current_user.locations]
        if not user_location_ids:
            # Return a query that finds nothing
            return Location.query.filter(db.false())
        return Location.query.filter(Location.id.in_(user_location_ids))


def get_dashboard_data():
    now = datetime.now()
    start_date = date(now.year, now.month, 1)
    end_date = date(now.year, now.month,
                    calendar.monthrange(now.year, now.month)[1])

    # RBAC: Filter data based on user's assigned locations
    user_locations = get_base_location_query().all()
    user_location_ids = [loc.id for loc in user_locations]

    all_clients = Client.query.all()
    all_spaces_in_scope = Space.query.filter(
        Space.location_id.in_(user_location_ids)).all()

    relevant_bookings = Booking.query.join(Space).filter(
        Space.location_id.in_(user_location_ids),
        Booking.end_date >= start_date,
        Booking.start_date <= end_date
    ).options(joinedload(Booking.space).joinedload(Space.location), joinedload(Booking.client)).all()

    income_by_location = {loc.name: 0.0 for loc in user_locations}
    income_by_client = {client.name: 0.0 for client in all_clients}
    grand_total_income = 0.0

    for b in relevant_bookings:
        income, _ = calculate_prorated_fee(b, start_date, end_date)
        if income > 0:
            if b.space.location.name in income_by_location:
                income_by_location[b.space.location.name] += income
            income_by_client[b.client.name] += income
            grand_total_income += income

    # Utilisation Summary Calculation
    under_utilised_summary = {}
    all_days_in_month = {
        start_date + timedelta(days=i) for i in range((end_date - start_date).days + 1)}
    bookings_by_space_id = {}
    for b in relevant_bookings:
        bookings_by_space_id.setdefault(b.space_id, []).append(b)

    for space in all_spaces_in_scope:
        space_bookings = bookings_by_space_id.get(space.id, [])
        booked_days = set()
        for b in space_bookings:
            overlap_start, overlap_end = max(
                b.start_date, start_date), min(b.end_date, end_date)
            if overlap_start <= overlap_end:
                booked_days.update(overlap_start + timedelta(days=i)
                                   for i in range((overlap_end - overlap_start).days + 1))

        if len(all_days_in_month - booked_days) > 7:
            under_utilised_summary[space.location.name] = under_utilised_summary.get(
                space.location.name, 0) + 1

    sorted_locations = sorted(
        income_by_location.items(), key=lambda item: item[1], reverse=True)
    sorted_clients = sorted(income_by_client.items(),
                            key=lambda item: item[1], reverse=True)

    return {
        "grand_total_income": round(grand_total_income, 2),
        "top_3_locations": sorted_locations[:3],
        "bottom_3_locations": sorted(income_by_location.items(), key=lambda item: item[1])[:3],
        "top_3_clients": sorted_clients[:3],
        "month_name": now.strftime("%B %Y"),
        "under_utilised_summary": under_utilised_summary
    }


def get_space_tracking_data(filter_location, filter_space_name, filter_start_str, filter_end_str):
    """
    Core logic for fetching space availability data, now providing both grouped data
    for the list view and a flat list of calendar events for the chart.
    """
    grouped_space_data = {}
    under_utilised_summary = {}
    calendar_events = []  # New: A flat list to hold data for the chart

    filter_start_date = date.fromisoformat(filter_start_str)
    filter_end_date = date.fromisoformat(filter_end_str)

    space_query = Space.query.options(
        joinedload(Space.location)).join(Location)
    if current_user.role != 'admin':
        user_location_ids = [loc.id for loc in current_user.locations]
        if not user_location_ids:
            return {}, {}, []
        space_query = space_query.filter(
            Space.location_id.in_(user_location_ids))
    if filter_location:
        space_query = space_query.filter(Location.name == filter_location)
    if filter_space_name:
        space_query = space_query.filter(Space.name == filter_space_name)

    all_spaces = space_query.order_by(Location.name, Space.name).all()
    all_days_in_filter = {filter_start_date + timedelta(
        days=i) for i in range((filter_end_date - filter_start_date).days + 1)}

    for space in all_spaces:
        bookings = space.bookings.filter(
            Booking.end_date >= filter_start_date, Booking.start_date <= filter_end_date).all()
        booked_days = set()
        for b in bookings:
            overlap_start, overlap_end = max(
                b.start_date, filter_start_date), min(b.end_date, filter_end_date)
            if overlap_start <= overlap_end:
                booked_days.update(overlap_start + timedelta(days=i)
                                   for i in range((overlap_end - overlap_start).days + 1))

        unbooked_days_set = all_days_in_filter - booked_days
        unbooked_days_count = len(unbooked_days_set)
        loc_name = space.location.name

        if unbooked_days_count > 7:
            under_utilised_summary[loc_name] = under_utilised_summary.get(
                loc_name, 0) + 1

        location_group = grouped_space_data.setdefault(loc_name, [])
        location_group.append({
            'space_name': space.name,
            'unbooked_days': unbooked_days_count,
            'unbooked_ranges': [format_date_range(s, e) for s, e in group_dates_into_ranges(unbooked_days_set)],
            'is_available': unbooked_days_count == len(all_days_in_filter),
        })

        # New: Populate the calendar_events list
        for day in all_days_in_filter:
            status = "booked" if day in booked_days else "unbooked"
            calendar_events.append({
                "space_label": f"{loc_name} - {space.name}",
                "date": day.strftime("%Y-%m-%d"),
                "status": status
            })

    # The function now returns three items
    return grouped_space_data, under_utilised_summary, calendar_events


def get_revenue_data(filter_location, filter_client, filter_start_str, filter_end_str):
    """
    Calculates prorated income for all clients and locations matching the filters,
    ensuring that zero-income entries are included and respecting user permissions.
    """
    filter_start_date = date.fromisoformat(filter_start_str)
    filter_end_date = date.fromisoformat(filter_end_str)

    # --- Step 1: Get the definitive list of CLIENTS for the report ---
    client_query = Client.query
    if filter_client:
        client_query = client_query.filter(Client.id == int(filter_client))
    all_report_clients = client_query.order_by(Client.name).all()

    # --- Step 2: Get the definitive list of LOCATIONS for the report, respecting RBAC ---
    # Start with the base query that already handles user permissions.
    location_query = get_base_location_query()
    if filter_location:
        location_query = location_query.filter(
            Location.name == filter_location)
    all_report_locations = location_query.order_by(Location.name).all()

    if not all_report_clients or not all_report_locations:
        return {}, 0.0

    # --- Step 3: Get all relevant BOOKINGS in a single, efficient query ---
    client_ids = [c.id for c in all_report_clients]
    location_ids = [loc.id for loc in all_report_locations]

    relevant_bookings = Booking.query.join(Space).filter(
        Booking.client_id.in_(client_ids),
        Space.location_id.in_(location_ids),
        Booking.end_date >= filter_start_date,
        Booking.start_date <= filter_end_date
    ).all()

    # --- Step 4: Calculate income and store it in a lookup dictionary ---
    income_lookup = {}
    for b in relevant_bookings:
        prorated_fee, _ = calculate_prorated_fee(
            b, filter_start_date, filter_end_date)
        if prorated_fee > 0:
            lookup_key = (b.client_id, b.space.location_id)
            income_lookup[lookup_key] = income_lookup.get(
                lookup_key, 0.0) + prorated_fee

    # --- Step 5: Build the final report data structure ---
    report_data = {}
    overall_total = 0.0
    for client in all_report_clients:
        client_entry = report_data.setdefault(client.name, {
            'total': 0.0,
            'locations': {}
        })

        for location in all_report_locations:
            income = round(income_lookup.get((client.id, location.id), 0.0), 2)
            client_entry['locations'][location.name] = income
            client_entry['total'] += income

        client_entry['total'] = round(client_entry['total'], 2)
        overall_total += client_entry['total']

    return report_data, round(overall_total, 2)


def get_income_by_space(filter_location, filter_space, filter_start_str, filter_end_str):
    """
    Calculates prorated rental income for all spaces matching the filters,
    ensuring that spaces with zero income are included and respecting user permissions.
    """
    filter_start_date = date.fromisoformat(filter_start_str)
    filter_end_date = date.fromisoformat(filter_end_str)

    # --- CORRECTED QUERY LOGIC ---
    # Start the query directly from the Space model for a cleaner approach.
    space_query = Space.query.join(
        Location).options(joinedload(Space.location))

    # RBAC: Filter by the user's assigned locations if they are not an admin
    if current_user.role != 'admin':
        user_location_ids = [loc.id for loc in current_user.locations]
        if not user_location_ids:
            return 0.0, {}  # Return empty data if user has no assigned locations
        space_query = space_query.filter(
            Space.location_id.in_(user_location_ids))

    # Apply user-selected filters from the form
    if filter_location:
        space_query = space_query.filter(Location.name == filter_location)
    if filter_space:
        space_query = space_query.filter(Space.name == filter_space)

    # Fetch all spaces that match the criteria
    all_report_spaces = space_query.order_by(Location.name, Space.name).all()

    if not all_report_spaces:
        return 0.0, {}

    space_ids = [s.id for s in all_report_spaces]

    # --- The rest of the function remains the same ---
    # Get all relevant bookings for the found spaces
    relevant_bookings = Booking.query.filter(
        Booking.space_id.in_(space_ids),
        Booking.end_date >= filter_start_date,
        Booking.start_date <= filter_end_date
    ).all()

    # Calculate income and store it in a lookup dictionary
    income_by_space_id = {}
    for b in relevant_bookings:
        prorated_fee, _ = calculate_prorated_fee(
            b, filter_start_date, filter_end_date)
        if prorated_fee > 0:
            income_by_space_id[b.space_id] = income_by_space_id.get(
                b.space_id, 0.0) + prorated_fee

    # Build the final report data structure
    overall_total = 0.0
    report_data = {}
    for space in all_report_spaces:
        loc_name = space.location.name
        space_name = space.name

        income = round(income_by_space_id.get(space.id, 0.0), 2)

        location_entry = report_data.setdefault(loc_name, {
            'location_total': 0.0,
            'spaces': {}
        })

        location_entry['spaces'][space_name] = income
        location_entry['location_total'] += income
        overall_total += income

    overall_total = round(overall_total, 2)
    for data in report_data.values():
        data['location_total'] = round(data['location_total'], 2)

    return overall_total, report_data


# --- EVENT-DRIVEN AUDIT LOGGING ---
@event.listens_for(db.session, 'before_flush')
def log_db_changes(session, flush_context, instances):
    if not current_user or not current_user.is_authenticated:
        return

    for instance in session.deleted:
        if isinstance(instance, Booking):
            log = BookingAuditLog(booking_number=instance.booking_number, user_id=current_user.id, action='delete',
                                  details=f"Booking for client {instance.client.name} in {instance.space.name} deleted.")
            session.add(log)

    for instance in session.dirty:
        if isinstance(instance, Booking):
            state = db.inspect(instance)
            changes = {}
            for attr in state.attrs:
                hist = state.get_history(attr.key, True)
                if hist.has_changes():
                    old_val, new_val = hist.deleted[0], hist.added[0]
                    if isinstance(old_val, date):
                        old_val = old_val.strftime('%d-%m-%Y')
                    if isinstance(new_val, date):
                        new_val = new_val.strftime('%d-%m-%Y')
                    changes[attr.key] = (old_val, new_val)

            if changes:
                details_str = " ".join(
                    [f"{key.replace('_', ' ').title()} from '{old}' to '{new}'." for key, (old, new) in changes.items()])
                log = BookingAuditLog(
                    booking_number=instance.booking_number, booking_id=instance.id, user_id=current_user.id, action='update', details=details_str)
                session.add(log)


@event.listens_for(db.session, 'after_flush')
def log_new_booking(session, flush_context):
    if not current_user or not current_user.is_authenticated:
        return

    for instance in session.new:
        if isinstance(instance, Booking):
            # Check if a client is associated with the booking
            client_name = instance.client.name if instance.client else "N/A"

            details = f"Booking created for client {client_name} with fee ${instance.rental_fee:.2f}."

            log = BookingAuditLog(
                booking_number=instance.booking_number,
                booking_id=instance.id,
                user_id=current_user.id,
                action='create',
                details=details
            )
            session.add(log)


# --- Authentication & Authorization ---

@app.route('/')
def index():
    """
    Handles the root URL.
    - Redirects authenticated users to the dashboard.
    - Redirects unauthenticated users to the login page.
    """
    if current_user.is_authenticated:
        # If the user is already logged in, take them to the dashboard
        return redirect(url_for('dashboard'))
    else:
        # If the user is not logged in, take them to the login page
        return redirect(url_for('login'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You do not have permission to access this page.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))


@app.route('/account/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # --- Validation ---
        # 1. Check if the user's current password is correct
        if not current_user.check_password(current_password):
            flash('Your current password is incorrect. Please try again.', 'error')
        # 2. Check if the new password and confirmation match
        elif new_password != confirm_password:
            flash('The new password and confirmation do not match.', 'error')
        # 3. Check if the new password is not empty
        elif not new_password:
            flash('The new password cannot be empty.', 'error')
        else:
            # --- Success Case ---
            # All checks passed, so we can set the new password and save it
            current_user.set_password(new_password)
            db.session.commit()
            flash('Your password has been changed successfully.', 'success')
            return redirect(url_for('dashboard'))

    # For GET requests, just render the form page
    return render_template('change_password.html')

# --- Main Application Routes ---


@app.route('/dashboard')
@login_required
def dashboard():
    # --- Date Setup for the ENTIRE Current Month ---
    today = date.today()
    start_of_month = today.replace(day=1)
    _, num_days_in_month = calendar.monthrange(today.year, today.month)
    end_of_month = today.replace(day=num_days_in_month)
    formatted_month = today.strftime('%B %Y')

    # --- Role-Based Access Control (RBAC) Filter ---
    # This block curates the data source based on the user's role.
    if current_user.role == 'admin':
        # Admins see all bookings for the month
        all_bookings_this_month = Booking.query.filter(
            Booking.end_date >= start_of_month,
            Booking.start_date <= end_of_month
        ).options(joinedload(Booking.space).joinedload(Space.location), joinedload(Booking.client)).all()
        # Admins see the total count of all spaces
        total_spaces = Space.query.count()
    else:
        # Regular users only see data from their assigned locations
        user_location_ids = [loc.id for loc in current_user.locations]

        # Filter bookings to only include those in the user's locations
        all_bookings_this_month = Booking.query.join(Space).filter(
            Space.location_id.in_(user_location_ids),
            Booking.end_date >= start_of_month,
            Booking.start_date <= end_of_month
        ).options(joinedload(Booking.space).joinedload(Space.location), joinedload(Booking.client)).all()

        # Count only the spaces within the user's assigned locations
        total_spaces = Space.query.filter(
            Space.location_id.in_(user_location_ids)).count()

    # --- All subsequent calculations now use the pre-filtered data ---

    # 1. Calculate Prorated Income
    current_month_income = sum(
        calculate_prorated_fee(b, start_of_month, end_of_month)[0] for b in all_bookings_this_month
    )

    # 2. Calculate Average Space Utilization
    utilization_percentage = 0
    if total_spaces > 0:
        total_booked_days_this_month = 0
        for b in all_bookings_this_month:
            overlap_start = max(b.start_date, start_of_month)
            overlap_end = min(b.end_date, end_of_month)
            if overlap_end >= overlap_start:
                total_booked_days_this_month += (overlap_end -
                                                 overlap_start).days + 1

        total_possible_space_days = total_spaces * num_days_in_month
        if total_possible_space_days > 0:
            utilization_percentage = (
                total_booked_days_this_month / total_possible_space_days * 100)

    # 3. Get Top Vendors & Locations by Prorated Income
    vendor_revenue = {}
    location_revenue = {}
    for b in all_bookings_this_month:
        prorated_fee_this_month = calculate_prorated_fee(
            b, start_of_month, end_of_month)[0]
        vendor_revenue[b.client.name] = vendor_revenue.get(
            b.client.name, 0) + prorated_fee_this_month
        location_revenue[b.space.location.name] = location_revenue.get(
            b.space.location.name, 0) + prorated_fee_this_month

    # Prepare data for charts
    sorted_vendors = sorted(vendor_revenue.items(),
                            key=lambda item: item[1], reverse=True)[:3]
    vendor_chart_labels = [item[0] for item in sorted_vendors]
    vendor_chart_data = [round(item[1], 2) for item in sorted_vendors]

    sorted_locations = sorted(location_revenue.items(
    ), key=lambda item: item[1], reverse=True)[:3]
    location_chart_labels = [item[0] for item in sorted_locations]
    location_chart_data = [round(item[1], 2) for item in sorted_locations]

    # Package all data for the template
    dashboard_data = {
        'current_month_income': current_month_income,
        'space_utilization': {
            'percentage': utilization_percentage,
            'booked': f"Avg. for {num_days_in_month} day(s)",
            'total': f"across {total_spaces} spaces"
        },
        'formatted_month': formatted_month,
        'charts': {
            'vendors': {'labels': vendor_chart_labels, 'data': vendor_chart_data},
            'locations': {'labels': location_chart_labels, 'data': location_chart_data}
        }
    }

    return render_template('dashboard.html', data=dashboard_data)


@app.route('/book', methods=['GET', 'POST'])
@login_required
def book_space():
    # --- Step 1: Handle the POST request (final booking submission) ---
    if request.method == 'POST':
        try:
            # Get all required data from the form
            space_id = int(request.form['space_id'])
            client_id = int(request.form['client_id'])
            start_date_obj = date.fromisoformat(request.form['start_date'])
            end_date_obj = date.fromisoformat(request.form['end_date'])
            rental_fee = float(request.form['rental_fee'])
            # For redirecting on error
            location_id = int(request.form['location_id'])
        except (ValueError, KeyError):
            flash("Invalid form data submitted. Please check all fields.", "error")
            return redirect(url_for('book_space'))

        # --- Validation for the booking ---
        if end_date_obj < start_date_obj:
            flash('Error: End date cannot be before the start date.', "error")
            return redirect(url_for('book_space', location_id=location_id))

        # Check for overlapping bookings
        overlapping = Booking.query.filter(
            Booking.space_id == space_id,
            Booking.end_date >= start_date_obj,
            Booking.start_date <= end_date_obj
        ).first()

        if overlapping:
            flash(
                f'<b>Booking failed:</b> This space is already booked from {overlapping.start_date.strftime("%d-%m-%Y")} to {overlapping.end_date.strftime("%d-%m-%Y")}.', 'error')
            return redirect(url_for('book_space', location_id=location_id))

        # --- If validation passes, create the booking ---
        new_booking = Booking(
            booking_number=get_next_booking_number(),
            space_id=space_id,
            client_id=client_id,
            start_date=start_date_obj,
            end_date=end_date_obj,
            rental_fee=rental_fee
        )
        db.session.add(new_booking)
        db.session.commit()

        flash(
            f'Booking #{new_booking.booking_number} created successfully!', 'success')
        return redirect(url_for('list_bookings'))

    # --- Step 2: Handle GET requests (displaying the form) ---
    locations = Location.query.order_by(Location.name).all()
    clients = Client.query.order_by(Client.name).all()
    selected_location = None

    # Check if a location was chosen from the first dropdown
    location_id = request.args.get('location_id', type=int)
    if location_id:
        selected_location = Location.query.get(location_id)

    return render_template('book.html',
                           locations=locations,
                           clients=clients,
                           selected_location=selected_location)


# --- REPLACE your existing edit_booking function with this complete version ---

@app.route('/bookings/<int:booking_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_booking(booking_id):
    booking = Booking.query.options(
        joinedload(Booking.space).joinedload(Space.location),
        joinedload(Booking.client)
    ).get_or_404(booking_id)

    # Role-based access control check
    user_location_ids = [loc.id for loc in current_user.locations]
    if current_user.role != 'admin' and booking.space.location_id not in user_location_ids:
        flash("You do not have permission to edit this booking.", "error")
        return redirect(url_for('list_bookings'))

    if request.method == 'POST':
        try:
            # 1. Convert form data to correct types
            space_id = int(request.form['space_id'])
            client_id = int(request.form['client_id'])
            start_date_obj = date.fromisoformat(request.form['start_date'])
            end_date_obj = date.fromisoformat(request.form['end_date'])
            rental_fee = float(request.form['rental_fee'])
        except (ValueError, TypeError, KeyError):
            flash("Invalid form data. Please check all fields.", "error")
            return redirect(url_for('edit_booking', booking_id=booking.id))

        # 2. Perform validation
        if end_date_obj < start_date_obj:
            flash('End date cannot be before the start date.', "error")
            return redirect(url_for('edit_booking', booking_id=booking.id))

        # Check for overlaps, excluding the current booking itself
        overlapping = Booking.query.filter(
            Booking.id != booking_id,  # <-- Exclude self from check
            Booking.space_id == space_id,
            Booking.end_date >= start_date_obj,
            Booking.start_date <= end_date_obj
        ).first()

        if overlapping:
            flash(
                f"<b>Update failed:</b> This space is already booked from {overlapping.start_date.strftime('%d-%m-%Y')} to {overlapping.end_date.strftime('%d-%m-%Y')}.", "error")
            return redirect(url_for('edit_booking', booking_id=booking.id))

        # 3. Apply the changes to the booking object
        booking.space_id = space_id
        booking.client_id = client_id
        booking.start_date = start_date_obj
        booking.end_date = end_date_obj
        booking.rental_fee = rental_fee

        # 4. Commit the transaction
        db.session.commit()  # Now this will save the changes

        flash('Booking updated successfully.', "success")
        return redirect(url_for('list_bookings'))

    # For GET requests, fetch necessary data for the form
    clients = Client.query.order_by(Client.name).all()
    spaces_in_location = sorted(
        booking.space.location.spaces, key=lambda s: s.name)
    return render_template('booking_edit.html', booking=booking, clients=clients, spaces=spaces_in_location)


@app.route('/bookings/<int:booking_id>/delete', methods=['POST'])
@login_required
def delete_booking(booking_id):
    # Eagerly load related data so we can access it for the log details
    booking = Booking.query.options(
        joinedload(Booking.client),
        joinedload(Booking.space)
    ).get_or_404(booking_id)

    # Your existing RBAC check remains for security
    user_location_ids = [loc.id for loc in current_user.locations]
    if current_user.role != 'admin' and booking.space.location_id not in user_location_ids:
        flash("You do not have permission to delete this booking.", "error")
        return redirect(url_for('list_bookings'))

    # Now, proceed with deleting the booking object
    db.session.delete(booking)

    # Commit both the new log and the deletion in a single transaction
    db.session.commit()

    flash('Booking deleted successfully.', "success")
    return redirect(url_for('list_bookings'))


@app.route('/bookings', methods=['GET'])
@login_required
def list_bookings():
    # --- Get filter and pagination values from the URL ---
    page = request.args.get('page', 1, type=int)
    per_page = 20  # You can adjust the number of items per page
    filter_location = request.args.get('filter_location', '')
    filter_space = request.args.get('filter_space', '')
    filter_start_str = request.args.get('filter_start', '')
    filter_end_str = request.args.get('filter_end', '')
    fuzzy_search_term = request.args.get('fuzzy_search_term', '').strip()

    # --- RBAC and Data Fetching ---
    if current_user.role == 'admin':
        locations = Location.query.order_by(Location.name).all()
    else:
        locations = sorted(current_user.locations, key=lambda loc: loc.name)

    processed_bookings = []
    total_items = 0
    show_results = bool(filter_start_str and filter_end_str) or bool(
        fuzzy_search_term)

    if show_results:
        try:
            # --- Build and execute the database query ---
            query = Booking.query.options(
                joinedload(Booking.space).joinedload(Space.location),
                joinedload(Booking.client)
            ).join(Booking.space)

            # (Apply DB-level filters as before...)
            if current_user.role != 'admin':
                user_location_ids = [loc.id for loc in current_user.locations]
                query = query.filter(Space.location_id.in_(user_location_ids))
            if filter_location:
                query = query.join(Space.location).filter(
                    Location.name == filter_location)
            if filter_space:
                query = query.filter(Space.name == filter_space)
            if filter_start_str and filter_end_str:
                filter_start_date = date.fromisoformat(filter_start_str)
                filter_end_date = date.fromisoformat(filter_end_str)
                query = query.filter(
                    Booking.end_date >= filter_start_date, Booking.start_date <= filter_end_date)

            bookings_from_db = query.order_by(Booking.start_date.desc()).all()

            # --- Apply Fuzzy Search in Python ---
            final_bookings = []
            if fuzzy_search_term:
                SCORE_THRESHOLD = 70
                for b in bookings_from_db:
                    score = fuzz.partial_ratio(
                        fuzzy_search_term, b.booking_number)
                    if score >= SCORE_THRESHOLD:
                        final_bookings.append(b)
            else:
                final_bookings = bookings_from_db

            # --- Manual Pagination on the final list ---
            total_items = len(final_bookings)
            start_index = (page - 1) * per_page
            end_index = start_index + per_page
            paginated_items = final_bookings[start_index:end_index]

            # --- Process only the paginated items for display ---
            for b in paginated_items:
                start_date_for_calc = date.fromisoformat(
                    filter_start_str) if filter_start_str else b.start_date
                end_date_for_calc = date.fromisoformat(
                    filter_end_str) if filter_end_str else b.end_date
                prorated_fee, days_counted = calculate_prorated_fee(
                    b, start_date_for_calc, end_date_for_calc)
                processed_bookings.append({
                    'id': b.id, 'booking_number': b.booking_number, 'location_name': b.space.location.name,
                    'space_name': b.space.name, 'client_name': b.client.name,
                    'start_date': b.start_date.strftime('%Y-%m-%d'), 'end_date': b.end_date.strftime('%Y-%m-%d'),
                    'rental_fee': b.rental_fee, 'days_counted': days_counted, 'prorated_rental_fee': prorated_fee,
                })

        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", "error")
            show_results = False

    # Create a simple pagination object to pass to the template
    pagination = {
        'page': page,
        'per_page': per_page,
        'total_items': total_items,
        'total_pages': (total_items + per_page - 1) // per_page
    }

    return render_template('bookings_list.html',
                           filtered_bookings=processed_bookings,
                           locations=locations,
                           show_results=show_results,
                           pagination=pagination,  # Pass the pagination object
                           # Pass all filter values back to maintain state
                           filter_location=filter_location,
                           filter_space=filter_space,
                           filter_start=filter_start_str,
                           filter_end=filter_end_str,
                           fuzzy_search_term=fuzzy_search_term)


@app.route('/reports/available_spaces')
@login_required
def available_spaces():
    filter_location, filter_space = request.args.get(
        'filter_location', ''), request.args.get('filter_space', '')
    filter_start, filter_end = request.args.get(
        'filter_start', ''), request.args.get('filter_end', '')

    locations = get_base_location_query().order_by(Location.name).all()

    grouped_space_data, under_utilised_summary, calendar_events = {}, {}, []
    show_results = filter_start and filter_end

    if show_results:
        try:
            # Unpack all three return values from the helper
            grouped_space_data, under_utilised_summary, calendar_events = get_space_tracking_data(
                filter_location, filter_space, filter_start, filter_end
            )
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", "error")
            show_results = False

    return render_template('available_spaces.html',
                           locations=locations,
                           grouped_space_data=grouped_space_data,
                           under_utilised_summary=under_utilised_summary,
                           calendar_events=calendar_events,  # Pass new data to the template
                           show_results=show_results,
                           filter_location=filter_location,
                           filter_space=filter_space,
                           filter_start=filter_start,
                           filter_end=filter_end)


@app.route('/reports/client_revenue')
@login_required
def client_revenue():
    # Get filter values from the URL query string
    filter_location = request.args.get('filter_location', '')
    filter_client = request.args.get('filter_client', '')
    filter_start = request.args.get('filter_start', '')
    filter_end = request.args.get('filter_end', '')

    # Use the RBAC-aware helper to get only the locations the user is allowed to see.
    locations = get_base_location_query().order_by(Location.name).all()
    clients = Client.query.order_by(Client.name).all()

    # Initialize variables with default values.
    report_data = {}
    overall_total = 0.0  # Use 'overall_total' for consistency
    show_results = filter_start and filter_end

    if show_results:
        try:
            # Correctly unpack the two values from the helper function.
            # The second value is the total, which we assign to 'overall_total'.
            report_data, overall_total = get_revenue_data(
                filter_location, filter_client, filter_start, filter_end
            )
        except (ValueError, TypeError):
            flash("Invalid filter parameters. Please check your inputs.", "error")
            show_results = False

    # --- THIS IS THE CORRECTED LINE ---
    # Pass the variable to the template using the name the template expects: 'overall_total'.
    return render_template('client_revenue.html',
                           locations=locations,
                           clients=clients,
                           revenue_data=report_data,
                           overall_total=overall_total,  # This now matches the template
                           show_results=show_results,
                           filter_location=filter_location,
                           filter_client=filter_client,
                           filter_start=filter_start,
                           filter_end=filter_end)


@app.route('/reports/income_by_space')
@login_required
def income_by_space():
    # Get filter values from the URL query string
    filter_location = request.args.get('filter_location', '')
    filter_space = request.args.get('filter_space', '')
    filter_start = request.args.get('filter_start', '')
    filter_end = request.args.get('filter_end', '')

    # Use the RBAC-aware helper to get only the locations the user is allowed to see
    locations = get_base_location_query().order_by(Location.name).all()

    # --- THE CRITICAL FIX IS HERE ---
    # 1. Initialize all variables with default values to prevent errors on initial page load.
    report_data = {}
    overall_total = 0.0
    show_results = filter_start and filter_end

    if show_results:
        try:
            # 2. Correctly unpack BOTH values returned by the helper function.
            # This assigns the calculated total to the 'overall_total' variable.
            overall_total, report_data = get_income_by_space(
                filter_location, filter_space, filter_start, filter_end
            )
        except (ValueError, TypeError):
            flash("Invalid filter parameters. Please check your inputs.", "error")
            show_results = False

    # 3. Explicitly pass the 'overall_total' variable to the template.
    return render_template('income_by_space.html',
                           locations=locations,
                           report_data=report_data,
                           overall_total=overall_total,  # This makes it available in the HTML
                           show_results=show_results,
                           filter_location=filter_location,
                           filter_space=filter_space,
                           filter_start=filter_start,
                           filter_end=filter_end)

# --- Reporting Routes ---


@app.route('/reports/client_revenue/export')
@login_required
def export_client_revenue():
    # --- Step 1: Get filter parameters (This part stays the same) ---
    filter_location = request.args.get('filter_location', '')
    filter_client = request.args.get('filter_client', '')
    filter_start = request.args.get('filter_start', '')
    filter_end = request.args.get('filter_end', '')

    if not (filter_start and filter_end):
        return "Error: Start and end dates are required for export.", 400

    # --- Step 2: Get your data using the existing helper function ---
    try:
        revenue_data, _ = get_revenue_data(
            filter_location, filter_client, filter_start, filter_end
        )
    except (ValueError, TypeError):
        return "Error: Invalid filter parameters for export.", 400

    # --- Step 3: Create the Dataset with tablib ---
    headers = ("Client", "Location", "Prorated Revenue")
    data = tablib.Dataset(headers=headers)

    # Flatten the nested dictionary data into a list of rows
    for client_name, data_dict in sorted(revenue_data.items()):
        for loc_name, revenue in sorted(data_dict['locations'].items()):
            data.append((client_name, loc_name, revenue))

    # --- Step 4: Prepare the file for download ---
    file_data = io.BytesIO()
    file_data.write(data.export('xlsx'))
    file_data.seek(0)

    file_name = f"client_revenue_{filter_start}_to_{filter_end}.xlsx"

    # --- Step 5: Return a Flask Response object ---
    return app.response_class(
        file_data.read(),
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition': f'attachment;filename={file_name}'}
    )


@app.route('/reports/available_spaces/export')
@login_required
def export_space_tracking():
    # --- Step 1: Get filter parameters (This part stays the same) ---
    filter_location = request.args.get('filter_location', '')
    filter_space = request.args.get('filter_space', '')
    filter_start = request.args.get('filter_start', '')
    filter_end = request.args.get('filter_end', '')

    if not (filter_start and filter_end):
        return "Error: Start and end dates are required for export.", 400

    # --- Step 2: Get your data (This part also stays the same) ---
    try:
        grouped_space_data, _, _ = get_space_tracking_data(
            filter_location, filter_space, filter_start, filter_end
        )
    except (ValueError, TypeError):
        return "Error: Invalid filter parameters for export.", 400

    # --- Step 3: Create the Dataset with tablib (This is the new part) ---

    # Define the headers for your Excel file
    headers = ("Location", "Space", "Unbooked Days", "Available Ranges")
    data = tablib.Dataset(headers=headers)

    # Loop through your data and append it to the dataset
    for location_name, spaces_in_location in sorted(grouped_space_data.items()):
        for space_data in spaces_in_location:
            data.append((
                location_name,
                space_data['space_name'],
                space_data['unbooked_days'],
                ", ".join(space_data['unbooked_ranges']
                          ) if space_data['unbooked_ranges'] else "None"
            ))

    # --- Step 4: Prepare the file for download ---

    # Create an in-memory binary stream to hold the Excel file data
    file_data = io.BytesIO()
    file_data.write(data.export('xlsx'))
    file_data.seek(0)  # Rewind the stream to the beginning

    file_name = f"space_tracking_{filter_start}_to_{filter_end}.xlsx"

    # --- Step 5: Return a Flask Response object ---
    return app.response_class(
        file_data.read(),
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition': f'attachment;filename={file_name}'}
    )


@app.route('/reports/income_by_space/export')
@login_required
def export_income_by_space():
    # --- Step 1: Get filter parameters (This part stays the same) ---
    filter_location = request.args.get('filter_location', '')
    filter_space = request.args.get('filter_space', '')
    filter_start = request.args.get('filter_start', '')
    filter_end = request.args.get('filter_end', '')

    if not (filter_start and filter_end):
        return "Error: Start and end dates are required for export.", 400

    # --- Step 2: Get your data using the existing helper function ---
    try:
        _, report_data = get_income_by_space(
            filter_location, filter_space, filter_start, filter_end
        )
    except (ValueError, TypeError):
        return "Error: Invalid filter parameters for export.", 400

    # --- Step 3: Create the Dataset with tablib ---
    headers = ("Location", "Space", "Income")
    data = tablib.Dataset(headers=headers)

    # Flatten the nested dictionary data into a list of rows
    for location_name, data_dict in sorted(report_data.items()):
        for space_name, income in sorted(data_dict['spaces'].items()):
            data.append((location_name, space_name, income))

    # --- Step 4: Prepare the file for download ---
    file_data = io.BytesIO()
    file_data.write(data.export('xlsx'))
    file_data.seek(0)

    file_name = f"income_by_space_{filter_start}_to_{filter_end}.xlsx"

    # --- Step 5: Return a Flask Response object ---
    return app.response_class(
        file_data.read(),
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition': f'attachment;filename={file_name}'}
    )

# --- Settings Routes (Admin Only) ---


@app.route('/settings/locations')
@login_required
@admin_required
def list_locations():
    locations = Location.query.options(subqueryload(
        Location.spaces)).order_by(Location.name).all()
    return render_template('locations_list.html', locations=locations)


@app.route('/settings/locations/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_location():
    if request.method == 'POST':
        name = request.form.get('name')

        # --- Validation Checks ---
        if not name:
            flash("Location name cannot be empty.", 'error')
        elif Location.query.filter_by(name=name).first():
            flash(
                f"A location with the name '{name}' already exists.", 'error')
        else:
            # --- Success Case ---
            # If all checks pass, create the location and redirect.
            new_location = Location(name=name)
            db.session.add(new_location)
            db.session.commit()
            flash(f"Location '{name}' created successfully.", 'success')
            return redirect(url_for('list_locations'))

        # --- THIS IS THE CRITICAL CHANGE ---
        # If validation fails, re-render the form template directly.
        # This allows us to pass the invalid name back to the form to be displayed.
        return render_template('location_form.html',
                               action='Create',
                               location=None,
                               name=name)  # Pass the invalid name back

    # For GET requests, render the form normally.
    return render_template('location_form.html', action='Create', location=None, name='')


@app.route('/settings/locations/<int:loc_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_location(loc_id):

    # Use the uppercase 'Location' class to query the database.
    # This fetches the specific location object and assigns it to the lowercase 'location' variable.
    location = Location.query.get_or_404(loc_id)

    if request.method == 'POST':
        # Get the new name from the form
        name = request.form.get('name')

        # Check for uniqueness, excluding the current location's name
        if name and not Location.query.filter(Location.id != loc_id, Location.name == name).first():
            location.name = name  # Update the name on the instance
            db.session.commit()
            flash(f"Location '{name}' updated successfully.", 'success')
            return redirect(url_for('list_locations'))

        flash("Location name is required and must be unique.", 'error')

    # For GET requests, render the form, passing the fetched location instance
    return render_template('location_form.html', action='Edit', location=location)

# ... (All other create/edit routes for spaces, clients, and users go here, each with admin protection) ...


@app.route('/settings/users')
@login_required
@admin_required
def list_users():
    users = User.query.order_by(User.full_name).all()
    return render_template('user_list.html', users=users)


@app.route('/settings/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    if request.method == 'POST':
        # Get user details from the form
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        # --- Validation ---
        if not all([full_name, email, password, role]):
            flash("All fields are required.", "error")
        elif User.query.filter_by(email=email).first():
            flash('An account with this email address already exists.', 'error')
        else:
            # --- User Creation Logic ---
            new_user = User(
                full_name=full_name,
                email=email,
                role=role
            )
            new_user.set_password(password)

            # Assign selected locations to the user
            location_ids = request.form.getlist('locations')
            new_user.locations = Location.query.filter(
                Location.id.in_(location_ids)).all()

            db.session.add(new_user)
            db.session.commit()

            # --- THIS IS THE ADDED LINE ---
            # Flash a success message to provide feedback to the admin.
            flash(
                f"User '{new_user.full_name}' created successfully.", 'success')

            return redirect(url_for('list_users'))

    # For GET requests, render the form
    locations = Location.query.order_by(Location.name).all()
    return render_template('user_form.html', action="Create", user=None, locations=locations)


@app.route('/settings/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    # --- THIS IS THE CRITICAL LINE THAT WAS MISSING ---
    # Fetch the user to be edited from the database, or return a 404 error if not found.
    # This defines the 'user_to_edit' variable for the rest of the function.
    user_to_edit = User.query.get_or_404(user_id)

    if request.method == 'POST':
        # Get updated data from the form
        user_to_edit.full_name = request.form.get('full_name')
        user_to_edit.email = request.form.get('email')
        user_to_edit.role = request.form.get('role')

        # Optionally update password if a new one is provided
        password = request.form.get('password')
        if password:
            user_to_edit.set_password(password)

        # Update assigned locations
        location_ids = request.form.getlist('locations')
        user_to_edit.locations = Location.query.filter(
            Location.id.in_(location_ids)).all()

        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('list_users'))

    # For GET requests, render the form with the user's existing data
    locations = Location.query.order_by(Location.name).all()
    return render_template('user_form.html',
                           action="Edit",
                           user=user_to_edit,
                           locations=locations)


@app.route('/settings/clients')
@login_required
@admin_required
def list_clients():
    clients = Client.query.order_by(Client.name).all()
    return render_template('clients_list.html', clients=clients)

# --- AJAX Endpoints ---


@app.route('/spaces_for_location', methods=['POST'])
@login_required
def spaces_for_location():
    location_name = request.form.get('location_name')
    location = get_base_location_query().filter_by(name=location_name).first()
    if not location:
        return jsonify({'spaces': []})
    sorted_spaces = sorted(location.spaces, key=lambda s: s.name)
    return jsonify({'spaces': [{'id': s.id, 'name': s.name} for s in sorted_spaces]})


@app.route('/locations/<int:loc_id>/spaces/<int:space_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_space(loc_id, space_id):
    # Fetch the specific space object to be edited, or return a 404 error if not found.
    space = Space.query.get_or_404(space_id)
    location = Location.query.get_or_404(loc_id)

    if request.method == 'POST':
        new_name = request.form.get('name', '').strip()

        # --- Validation ---
        if not new_name:
            flash("Space Name cannot be empty.", "error")
        else:
            # Check if another space in the same location already has the new name
            existing_space = Space.query.filter(
                Space.location_id == loc_id,
                Space.name == new_name,
                Space.id != space_id  # Exclude the current space from the check
            ).first()

            if existing_space:
                flash(
                    f"Error: A space with the name '{new_name}' already exists in this location.", "error")
            else:
                space.name = new_name
                db.session.commit()
                flash(
                    f"Space '{space.name}' has been updated successfully.", "success")
                return redirect(url_for('list_locations'))

    # For a GET request, render the form and pass the existing space data to it.
    return render_template('space_form.html',
                           action="Edit",
                           space=space,
                           location=location)


@app.route('/settings/locations/<int:loc_id>/spaces/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_space(loc_id):
    # Fetch the parent location to provide context and for creating the new space
    location = Location.query.get_or_404(loc_id)

    if request.method == 'POST':
        # Get the new space's name from the form
        name = request.form.get('name')
        if not name:
            flash("Space name cannot be empty.", "error")
        else:
            # Create the new space and associate it with the correct location using loc_id
            new_space = Space(name=name, location_id=loc_id)
            db.session.add(new_space)
            db.session.commit()
            flash(
                f"Space '{name}' created successfully for {location.name}.", "success")
            return redirect(url_for('list_locations'))

    # For GET requests, render the form, passing the parent location for context
    return render_template('space_form.html',
                           action='Create',
                           space=None,
                           location=location)


@app.route('/clients/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_client():
    if request.method == 'POST':
        # Correctly get both 'name' and 'code' from the form
        name = request.form.get('name', '').strip()
        code = request.form.get('code', '').strip().upper()

        # --- Validation ---
        if not name or not code:
            flash("Both Vendor Name and Vendor Code are required.", "error")
        elif Client.query.filter_by(code=code).first():
            flash(f"Error: Vendor Code '{code}' is already taken.", "error")
        elif Client.query.filter_by(name=name).first():
            flash(f"Error: Vendor Name '{name}' is already taken.", "error")
        else:
            # Create the new client with both name and code
            new_client = Client(name=name, code=code)
            db.session.add(new_client)
            db.session.commit()
            flash(
                f"Vendor '{name}' (Code: {code}) created successfully.", "success")
            return redirect(url_for('list_clients'))

    return render_template('client_form.html', action="Create", client=None)


@app.route('/clients/<int:client_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_client(client_id):
    client = Client.query.get_or_404(client_id)
    if request.method == 'POST':
        # Correctly get both 'name' and 'code' from the form
        name = request.form.get('name', '').strip()
        code = request.form.get('code', '').strip().upper()

        # --- Validation ---
        if not name or not code:
            flash("Both Vendor Name and Vendor Code are required.", "error")
        else:
            # Check if the new code/name is taken by ANOTHER client
            existing_code = Client.query.filter(
                Client.code == code, Client.id != client_id).first()
            existing_name = Client.query.filter(
                Client.name == name, Client.id != client_id).first()

            if existing_code:
                flash(
                    f"Error: Vendor Code '{code}' is already in use by another vendor.", "error")
            elif existing_name:
                flash(
                    f"Error: Vendor Name '{name}' is already in use by another vendor.", "error")
            else:
                client.name = name
                client.code = code
                db.session.commit()
                flash(
                    f"Vendor '{client.name}' updated successfully.", "success")
                return redirect(url_for('list_clients'))

    return render_template('client_form.html', action="Edit", client=client)


@app.route('/settings/audit-logs')
@login_required
@admin_required
def list_audit_logs():
    page = request.args.get('page', 1, type=int)

    # Get filter values from the form
    filter_user = request.args.get('user', '')
    filter_action = request.args.get('action', '')

    query = BookingAuditLog.query

    # Apply filters to the query
    if filter_user:
        query = query.join(User).filter(
            User.full_name.ilike(f'%{filter_user}%'))
    if filter_action:
        query = query.filter(BookingAuditLog.action == filter_action)

    pagination = query.order_by(BookingAuditLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    audit_logs = pagination.items

    return render_template('audit_logs_list.html',
                           audit_logs=audit_logs,
                           pagination=pagination,
                           # Pass filter values back to re-populate the form
                           filter_user=filter_user,
                           filter_action=filter_action)

# --- End of Settings Routes ---


@app.before_request
def create_initial_admin():
    # This function will run once before the first request.
    # We use a global flag to ensure it only tries to create the admin once per app start.
    if not app.config.get('ADMIN_CREATED'):
        with app.app_context():
            # Check if an admin user already exists
            if not User.query.filter_by(email='admin@example.com').first():
                print("Admin user not found. Creating one...")

                # Create the admin user object
                admin_user = User(
                    full_name='Admin User',
                    email='admin@example.com',
                    role='admin'
                )
                # Set a default password. CHANGE THIS after logging in.
                admin_user.set_password('changethispassword')

                # Assign all existing locations to the admin user
                all_locations = Location.query.all()
                admin_user.locations = all_locations

                db.session.add(admin_user)
                db.session.commit()
                print("Admin user created successfully.")
            else:
                print("Admin user already exists.")

        # Set the flag to prevent this from running again
        app.config['ADMIN_CREATED'] = True


@app.cli.command("init-booking-sequence")
def init_booking_sequence():
    """Initializes the booking number sequence counter."""
    # Check if the sequence has already been initialized
    if BookingSequence.query.get(1):
        print("Booking sequence already initialized.")
        return

    # Create the first sequence entry, starting at 1
    sequence = BookingSequence(id=1, next_value=1)
    db.session.add(sequence)
    db.session.commit()
    print("Booking number sequence has been initialized successfully.")

# --- End of the new block ---


# --- Main Execution ---
if __name__ == '__main__':
    with app.app_context():
        # This is for development. In production, use Flask-Migrate commands.
        db.create_all()
    app.run(port=80, debug=True)
