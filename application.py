import os
import random
import string
import httplib2
import json
import requests
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for,\
    send_from_directory, jsonify, abort, session as login_session,\
    make_response

from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import func
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from werkzeug import secure_filename
from werkzeug.contrib.atom import AtomFeed


app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

with open('client_secret.json', 'r') as json_file:
    CLIENT_ID = json.loads(json_file.read())['web']['client_id']

# Info about view decorators in flask from here:
# http://flask.pocoo.org/docs/0.10/patterns/viewdecorators/

# This was modified from CSRF protection here:
# http://flask.pocoo.org/snippets/3/


def csrf_protected(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            token = login_session.pop('_csrf_token', None)
            if not token or token != request.form.get('_csrf_token'):
                abort(403)
        return f(*args, **kwargs)
    return decorated_function


def random_string():
    chars = string.ascii_uppercase + string.ascii_lowercase
    return ''.join(random.choice(chars) for _ in range(32))


def generate_csrf_token():
    if '_csrf_token' not in login_session:
        login_session['_csrf_token'] = random_string()
    return login_session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token


def user_logged_in():
    return 'username' in login_session

app.jinja_env.globals['user_logged_in'] = user_logged_in


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect(url_for('show_login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    # Subquery here inspired by
    # http://docs.sqlalchemy.org/en/latest/orm/tutorial.html#using-subqueries
    count_query = session.query(
        Item.category_id,
        func.count('*').label('item_count')
    ).group_by(Item.category_id).subquery()
    categories = []
    for category, count in session.query(Category, count_query.c.item_count)\
            .outerjoin(count_query, Category.id == count_query.c.category_id)\
            .limit(10).order_by(desc('item_count')):
        if count is None:
            count = 0
        categories.append({'name': category.name, 'count': count})
    items = session.query(Item).order_by(Item.created_date.desc())\
        .limit(10).all()
    return render_template('index.html', categories=categories, items=items)


@app.route('/login')
def show_login():
    state = random_string()
    login_session['state'] = state
    return render_template('login.html', STATE=state)


def json_response(error_message, http_status=401):
    """Makes a JSON error response for the code below
    :param error_message: the error message
    :param http_status: HTTP status code to use, defaults to 401
    :return: json response object
    """
    response = make_response(json.dumps(error_message), http_status)
    response.headers['Content-Type'] = 'application/json'
    return response


# Function below nearly verbatim from the Authorization and Authentication
# course


@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        return json_response('Invalid state parameter')
    code = request.data
    try:
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        return json_response('Failed to upgrade the authorization code.')
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
           access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    if result.get('error') is not None:
        return json_response(result.get('error'), 500)
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        return json_response("Token's user ID doesn't match given user ID")
    if result['issued_to'] != CLIENT_ID:
        return json_response("Token's client ID doesn't match app's ID")
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        return json_response('Current user is already connected.', 200)
    login_session['credentials'] = credentials.to_json()
    login_session['gplus_id'] = gplus_id
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    if get_user_id(login_session['email']) is None:
        create_user(login_session)
    login_session['user_id'] = get_user_id(login_session['email'])
    return '<h1>Welcome {}!</h1>'.format(login_session['username'])


@app.route('/logout')
def show_logout():
    credentials = login_session.get('credentials')
    logout_message = "You have been successfully logged out."
    detailed_message = ""
    if credentials is None:
        logout_message = "You are not currently logged in."
    else:
        credentials = json.loads(credentials)
        access_token = credentials['access_token']
        url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
              % access_token
        h = httplib2.Http()
        (headers, content) = h.request(url, 'GET')
        if headers['status'] == '200':
            detailed_message = 'Successfully disconnected from Google Plus.'
        else:
            detailed_message = 'Failed to revoke token for given user. ' + \
                               content + access_token
    for key in ['credentials', 'gplus_id', 'username', 'picture', 'email',
                'user_id']:
        if login_session.get(key):
            del login_session[key]
    return render_template('logout.html', logout_message=logout_message,
                           detailed_message=detailed_message)


@app.route('/categories/json')
def show_all_categories_json():
    categories = session.query(Category).all()
    return jsonify(Categories=[i.serialize for i in categories])


# This is directly from a Flask snippet related to Atom feeds
# http://flask.pocoo.org/snippets/10/

@app.route('/recent-categories.atom')
def recent_categories_feed():
    feed = AtomFeed('Recent Categories',
                    feed_url=request.url, url=request.url_root)
    categories = session.query(Category)\
        .order_by(Category.created_date.desc()).limit(15).all()
    for category in categories:
        feed.add(category.name, category.name,
                 content_type='html',
                 url=url_for('show_category', category=category.name),
                 updated=category.created_date
                 )
    return feed.get_response()


@app.route('/recent-items.atom')
def recent_items_feed():
    feed = AtomFeed('Recent Items',
                    feed_url=request.url, url=request.url_root)
    items = session.query(Item).order_by(Item.created_date.desc())\
        .limit(15).all()
    for item in items:
        feed.add(item.name, item.description,
                 content_type='html',
                 url=url_for('show_item', category=item.category.name,
                             name=item.name),
                 updated=item.created_date)
    return feed.get_response()


@app.route('/category/new', methods=['GET', 'POST'])
@csrf_protected
@login_required
def new_category():
    if request.method == 'POST':
        try:
            new_category = Category(name=request.form['name'])
            session.add(new_category)
            session.commit()
        except IntegrityError:
            session.rollback()
            return render_template('error.html', error_message="""
                <p>The category name you provided already exists.
                 <a href="{}">Click here</a> to view it.</p>
            """.format(url_for('show_category',
                               category=request.form['name'])))

        return redirect(url_for('show_category',
                                category=request.form['name']))
    else:
        return render_template('categories/new_category.html')


@app.route('/category/<string:category>/json')
def show_category_json(category):
    try:
        current_category = session.query(Category).filter_by(name=category)\
            .one()
    except NoResultFound:
        return json_response('Invalid category', 404)
    items = session.query(Item).filter_by(category=current_category).all()
    return jsonify(Category=current_category.name,
                   Items=[i.serialize for i in items])


@app.route('/category/<string:category>')
def show_category(category):
    try:
        current_category = session.query(Category).filter_by(name=category)\
            .one()
    except NoResultFound:
        return render_template('error.html', error_message="""
                <p>Invalid category. Click <a href="{}">here</a> to create a
                 new category.</p>
            """.format(url_for('new_category')))
    items = session.query(Item).filter_by(category=current_category).all()
    return render_template('categories/show_category.html', items=items,
                           categoryName=current_category.name)


@app.route('/item/<string:category>/new', methods=['GET', 'POST'])
@login_required
@csrf_protected
def new_item(category):
    try:
        current_category = session.query(Category).filter_by(name=category)\
            .one()
    except NoResultFound:
        return render_template('error.html', error_message="""
                <p>Invalid category. Click <a href="{}">here</a> to create a
                 new category.</p>
            """.format(url_for('new_category')))
    if request.method == 'POST':
        uploaded_picture = upload_file(request.files['picture'])
        try:
            if uploaded_picture:
                uploaded_picture = uploaded_picture[0]
            new_item = Item(
                name=request.form['name'],
                description=request.form['description'],
                user=get_logged_in_user(login_session),
                category=current_category,
                picture=uploaded_picture
            )
            session.add(new_item)
            session.commit()
        except IntegrityError:
            session.rollback()
            return render_template('error.html', error_message="""
                <p>The item name you provided already exists in this category.
                 <a href="{}">Click here</a> to view it.
            """.format(url_for('show_item', category=category,
                               name=request.form['name'])))
        return redirect(url_for('show_item', category=category,
                                name=request.form['name']))
    else:
        return render_template('items/new_item.html', category=category)


@app.route('/item/<string:category>/<string:name>/edit',
           methods=['GET', 'POST'])
@login_required
@csrf_protected
def edit_item(category, name):
    try:
        current_category = session.query(Category).filter_by(name=category)\
            .one()
    except NoResultFound:
        return render_template('error.html', error_message="""
                <p>Invalid category. Click <a href="{}">here</a> to create a
                new category.</p>
            """.format(url_for('new_category')))
    try:
        current_item = session.query(Item).filter_by(name=name).one()
    except NoResultFound:
        return render_template('error.html', error_message="""
                <p>Invalid item. Click <a href="{}">here</a> to view all items
                 in the '{}' category.</p>
            """.format(url_for('show_category',
                               category=current_category.name),
                       current_category.name))
    if current_item.owner_id != login_session['user_id']:
        return render_template('error.html', error_message="""
                <p>This item was not created by you, so you do not have the
                permissions to edit it. <a href="{}">Click here</a> to
                view it.</p>
            """.format(url_for('show_item',
                               category=current_category.name,
                               name=current_item.name)))
    if request.method == 'POST':
        uploaded_picture = upload_file(request.files['picture'])
        try:
            if uploaded_picture:
                uploaded_picture = uploaded_picture[0]

            current_item.name = request.form['name']
            current_item.description = request.form['description']
            if uploaded_picture:
                current_item.picture = uploaded_picture
            session.add(current_item)
            session.commit()
        except IntegrityError:
            session.rollback()
            return render_template('error.html', error_message="""
                <p>The item name you provided already exists in this category.
                <a href="{}">Click here</a> to view it.
            """.format(url_for('show_item', category=category,
                               name=request.form['name'])))
        return redirect(url_for('show_item', category=category,
                                name=request.form['name']))
    else:
        return render_template('items/edit_item.html', category=category,
                               item=current_item)


@app.route('/item/<string:category>/<string:name>/delete',
           methods=['GET', 'POST'])
@login_required
@csrf_protected
def delete_item(category, name):
    try:
        current_category = session.query(Category).filter_by(name=category)\
            .one()
    except NoResultFound:
        return render_template('error.html', error_message="""
                <p>Invalid category. Click <a href="{}">here</a> to create a
                new category.</p>
            """.format(url_for('new_category')))
    try:
        current_item = session.query(Item)\
            .filter_by(name=name, category=current_category).one()
    except NoResultFound:
        return render_template('error.html', error_message="""
                <p>Invalid item. Click <a href="{}">here</a> to view all items
                 in the '{}' category.</p>
            """.format(url_for('show_category',
                               category=current_category.name),
                       current_category.name))
    if current_item.owner_id != login_session['user_id']:
        return render_template('error.html', error_message="""
                <p>This item was not created by you, so you do not have the
                permissions to delete it. <a href="{}">Click here</a> to
                view it.</p>
            """.format(url_for('show_item',
                               category=current_category.name,
                               name=current_item.name)))
    if request.method == 'POST':
        try:
            session.delete(current_item)
            session.commit()
        except IntegrityError:
            session.rollback()
            return render_template('error.html', error_message="""
                <p>Could not delete the item.
                <a href="{}">Click here</a> to view it.
            """.format(url_for('show_item', category=category,
                               name=request.form['name'])))
        return redirect(url_for('show_category', category=category))
    else:
        return render_template('items/delete_item.html', category=category,
                               item=current_item)


@app.route('/item/<string:category>/<string:name>/view')
def show_item(category, name):
    try:
        current_category = session.query(Category).filter_by(name=category)\
            .one()
    except NoResultFound:
        return render_template('error.html', error_message="""
                <p>Invalid category. Click <a href="{}">here</a> to create a
                new category.</p>
            """.format(url_for('new_category')))
    try:
        item = session.query(Item).filter_by(category=current_category,
                                             name=name).one()
    except NoResultFound:
        return render_template('error.html', error_message="""
                <p>Invalid item. Click <a href="{}">here</a> to view all items
                 in the '{}' category.</p>
            """.format(url_for('show_category',
                               category=current_category.name),
                       current_category.name))

    return render_template('items/show_item.html', item=item,
                           categoryName=current_category.name)


def create_user(login_session):
    new_user = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture']
    )
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# Functions below nearly verbatim from the Authorization and Authentication
# course

def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def get_logged_in_user(login_session):
    user_id = get_user_id(login_session['email'])
    if user_id is not None:
        return get_user_info(user_id)
    return None


def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Upload code nearly verbatim from this section of the Flask docs:
# http://flask.pocoo.org/docs/0.10/patterns/fileuploads/

def upload_file(file):
    # Returns a tuple of the saved file name and its full URL.
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return filename, url_for('uploaded_file', filename=filename)
    return None


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    app.debug = False
    app.secret_key = 'super secret key sadfasdfsadf'
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.run(host='0.0.0.0', port=8000)
