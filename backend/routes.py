import threading
import time
from flask import Blueprint, request, session, url_for, abort
from flask import render_template, redirect, jsonify
from werkzeug.security import gen_salt
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from backend.models import db, User, OAuth2Client, Token
from backend.oauth2 import authorization, require_oauth
import requests

from backend.settings import SENDINBLUE_KEY, RECOVERY_SECS

bp = Blueprint('home', __name__)


def mail_send(message, subject, destination):
    r = requests.post(url="https://api.sendinblue.com/v3/smtp/email", headers={
        'accept': 'application/json',
        'api-key': SENDINBLUE_KEY,
        'content-type': 'application/json'
    }, json={
        'sender': {'name': 'AuthMaster', 'email': 'noreply@authmaster.fermitech.dev'},
        'to': [{'email': destination.email, 'name': destination.name + " " + destination.surname}],
        'subject': subject,
        'htmlContent': message
    })
    print(r.text)


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]


@bp.route('/', methods=('GET', 'POST'))
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        user: User = User.query.filter_by(username=username).first()
        if not user or user.check_password(request.form.get("password")):
            abort(403)
        session['id'] = user.id
        # if user is not just to log in, but need to head back to the auth page, then go for it
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect('/')
    user = current_user()
    if user:
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()
    else:
        clients = []

    return render_template('home.html', user=user, clients=clients)


@bp.route("/flow/lost_credentials/<int:step>", methods=["GET", "POST"])
def lost_credentials(step):
    user = current_user()
    if user:
        if request.method == "GET":
            return render_template('account_recovery/changepassword.html', user=user)
        abort(404)
    if step == 1:
        if request.method == "GET":
            return render_template('account_recovery/emailinput.html')
        else:
            user: User = User.query.filter_by(email=request.form.get("email")).first()
            session['restore_email'] = request.form.get("email")
            if not user:
                return redirect(url_for("lost_credentials", step=2))
            token = Token(user_id=user.id)
            db.session.add(token)
            db.session.commit()
            db.session.refresh(token)
            thread = threading.Thread(target=mail_send, args=(
                render_template("email/recovery.html", user=user, token=token), "Password Reset Request", user))
            thread.start()
            return redirect(url_for("home.lost_credentials", step=2))
    if step == 2:
        if request.method == "GET":
            return render_template('account_recovery/tokeninput.html')
        else:
            user: User = User.query.filter_by(email=session["restore_email"]).first()
            token: Token = Token.query.filter_by(user_id=user.id, value=request.form.get("token")).first()
            if not token:
                abort(401)
            if not token.is_valid(RECOVERY_SECS):
                db.session.delete(token)
                db.session.commit()
                abort(401)
            session["id"] = user.id
            session.pop("restore_email")
            db.session.delete(token)
            db.session.commit()
            return redirect(url_for("home.lost_credentials", step=3))
    abort(404)


@bp.route("/user/<int:uid>/edit", methods=["POST"])
def user_edit(uid):
    user: User = User.query.get_or_404(uid)
    if not user or (user.id != uid and not user.isAdmin):
        abort(403)
    user.username = request.form.get("username")
    user.email = request.form.get("email")
    user.name = request.form.get("name")
    user.surname = request.form.get("surname")
    db.session.commit()
    return redirect("/")


@bp.route("/user/<int:uid>/edit_psw", methods=["POST"])
def user_password_edit(uid):
    user: User = User.query.get_or_404(uid)
    if not user or (user.id != uid and not user.isAdmin):
        abort(403)
    user.password = User.gen_password(request.form.get("password"))
    db.session.commit()
    return redirect("/")


@bp.route('/logout')
def logout():
    del session['id']
    return redirect('/')


@bp.route('/admin/create_client', methods=('GET', 'POST'))
def create_client():
    user: User = current_user()
    if not user or not user.isAdmin:
        return redirect('/')
    if request.method == 'GET':
        return render_template('create_client.html')

    client_id = gen_salt(24)
    client_id_issued_at = int(time.time())
    client = OAuth2Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        user_id=user.id,
    )

    form = request.form
    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": form["client_uri"],
        "grant_types": split_by_crlf(form["grant_type"]),
        "redirect_uris": split_by_crlf(form["redirect_uri"]),
        "response_types": split_by_crlf(form["response_type"]),
        "scope": form["scope"],
        "token_endpoint_auth_method": form["token_endpoint_auth_method"]
    }
    client.set_client_metadata(client_metadata)

    if form['token_endpoint_auth_method'] == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)

    db.session.add(client)
    db.session.commit()
    return redirect('/')


@bp.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    user = current_user()
    # if user log status is not true (Auth server), then to log it in
    if not user:
        return redirect(url_for('home.home', next=request.url))
    if request.method == 'GET':
        try:
            grant = authorization.get_consent_grant(end_user=user)
        except OAuth2Error as error:
            return error.error
        return render_template('authorize.html', user=user, grant=grant)
    if not user and 'username' in request.form:
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
    if request.form['confirm']:
        grant_user = user
    else:
        grant_user = None
    return authorization.create_authorization_response(grant_user=grant_user)


@bp.route('/oauth/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()


@bp.route('/oauth/revoke', methods=['POST'])
def revoke_token():
    return authorization.create_endpoint_response('revocation')


@bp.route('/api/me')
@require_oauth('Profile')
def api_me():
    user = current_token.user
    return jsonify(id=user.id, username=user.username)
