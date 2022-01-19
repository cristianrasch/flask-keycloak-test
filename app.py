import functools
from datetime import datetime
from urllib.parse import parse_qs, quote_plus, urljoin, urlparse

import jwt
import requests
from flask import (
    Flask,
    abort,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from oidcrp.rp_handler import RPHandler
from oidcrp.service_context import DEFAULT_VALUE

app = Flask(__name__)
app.config.from_object("settings")
# app.config.from_envvar('APP_SETTINGS')

DEFAULT_VALUE["client_id"] = app.config["CLIENT_ID"]
DEFAULT_VALUE["client_secret"] = app.config["CLIENT_SECRET"]
DEFAULT_VALUE["redirect_uris"] = [app.config["REDIRECT_URI"]]
DEFAULT_VALUE["behaviour"] = {
    "response_types": ["code"],
    "scope": ["openid", "profile", "email"],
    "token_endpoint_auth_method": ["client_secret_basic", "client_secret_post"],
}
# BEHAVIOUR_ARGS = {
#     'response_types': ['code'],
#     'scope': ['openid', 'profile', 'email'],
#     'token_endpoint_auth_method': ['client_secret_basic', 'client_secret_post'],
# }
BASE_URL = f"{app.config['PREFERRED_URL_SCHEME']}://{app.config['SERVER_NAME']}"
RPH = RPHandler(BASE_URL, verify_ssl=False)


@app.route("/")
def index():
    return render_template("index.html")
    # if 'userinfo' in session:
    #     return redirect(url_for('users'))
    # else:
    #     return render_template('index.html')


@app.route("/login")
def login():
    info = RPH.begin(app.config["ISSUER_ID"].removesuffix("/"))
    # info = RPH.begin(app.config['ISSUER_ID'].removesuffix('/'),
    #                  behaviour_args=BEHAVIOUR_ARGS)
    session["state"] = info["state"]
    url = info["url"]
    query_string = urlparse(url).query
    qry_str_params = parse_qs(query_string)
    session["nonce"] = qry_str_params["nonce"][0]
    if next_ := request.args.get("next"):
        session["next"] = next_

    return redirect(url)


@app.route("/callback")
def callback():
    import sys
    from pprint import pprint

    session_state = session.pop("state")
    assert (
        request.args["state"] == session_state
    ), f"{request.args['state']=} != {session_state=}"
    print("---", file=sys.stderr)
    print("REQ ARGS:", file=sys.stderr)
    pprint(request.args, stream=sys.stderr)
    session_info = RPH.get_session_information(request.args["state"])
    print("SESSION INFO:", file=sys.stderr)
    pprint(session_info.to_dict(), stream=sys.stderr)
    res = RPH.finalize(session_info["iss"], request.args)
    session_nonce = session.pop("nonce")
    assert (
        res["id_token"]["nonce"] == session_nonce
    ), f"{res['id_token']['nonce']=} != {session_nonce=}"
    res["id_token"] = res.pop("id_token").to_dict()
    res["userinfo"] = res.pop("userinfo").to_dict()
    print("RES:", file=sys.stderr)
    pprint(res, stream=sys.stderr)
    print("---", file=sys.stderr)

    for k, v in res.items():
        session[k] = v

    return redirect(session.pop("next", None) or url_for("index"))
    # return jsonify(res)


@app.route("/session")
def inspect_session():
    return jsonify(session)


def refresh_access_token_if_necessary():
    token = session["token"]
    header = jwt.get_unverified_header(token)
    jwks_client = jwt.PyJWKClient(url_for("certs", _external=True))
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    data = {}
    access_token_refreshed = False

    while not data:
        try:
            return jwt.decode(
                token,
                signing_key.key,
                algorithms=header["alg"],
                audience="account",
                options={"verify_exp": True},
            )
        except jwt.exceptions.ExpiredSignatureError:
            import sys

            expiration_date = datetime.fromtimestamp(session["id_token"]["exp"])
            print("---", file=sys.stderr)
            print(f"Access token expired on: {expiration_date}", file=sys.stderr)
            print("---", file=sys.stderr)

            if access_token_refreshed:
                return data
            else:
                try:
                    access_token_resp = RPH.refresh_access_token(session["state"])
                except KeyError:
                    return data
                else:
                    session["token"] = token = access_token_resp["access_token"]
                    for k, v in access_token_resp.get(
                        "__verified_id_token", {}
                    ).items():
                        session["id_token"][k] = v
                    access_token_refreshed = True


@app.route("/validate_access_token")
def validate_access_token():
    if data := refresh_access_token_if_necessary():
        return jsonify(data)
    else:
        return redirect(f"{url_for('login')}?next={quote_plus(request.path)}")


@app.route("/certs")
def certs():
    resp = requests.get(
        urljoin(app.config["ISSUER_ID"], app.config["CERTS_ENDPOINT"]),
        verify=False,
    )
    resp.raise_for_status()
    res = resp.json()
    return jsonify({"keys": [key for key in res["keys"] if key["use"] == "sig"]})


def permission_required(permission):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not refresh_access_token_if_necessary():
                return abort(
                    redirect(f"{url_for('login')}?next={quote_plus(request.full_path)}")
                )

            resp = requests.post(
                urljoin(app.config["ISSUER_ID"], app.config["TOKEN_ENDPOINT"]),
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
                    "audience": current_app.config["CLIENT_ID"],
                    "permission": permission,
                    "response_mode": "decision",
                },
                headers={
                    "Authorization": f"Bearer {session['token']}",
                },
                verify=False,
            )
            res = resp.json()

            if resp.status_code == 403:
                return abort(make_response(jsonify(res), resp.status_code))

            if res.get("result", False):
                return func(*args, **kwargs)
            else:
                return abort(make_response(jsonify(res), resp.status_code))

        return wrapper

    return decorator


@app.route("/admins")
@permission_required("Admins")
def admins():
    return render_template("admins.html", admins=["Mike"])


@app.route("/users")
@permission_required("Users")
def users():
    return render_template("users.html", users=["Cristian", "Mike", "Rob"])


@app.route("/logout")
def logout():
    session.clear()
    url = urljoin(
        current_app.config["ISSUER_ID"], current_app.config["LOGOUT_ENDPOINT"]
    )
    url += "?redirect_uri="
    # Don't forget to add redirect_uri to the list of valid Redirect URIs for your
    # client app
    url += quote_plus(f"{BASE_URL}/")
    return redirect(url)
