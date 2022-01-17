from flask import Flask, jsonify, redirect, render_template, request, session
from oidcrp.rp_handler import RPHandler
from oidcrp.service_context import DEFAULT_VALUE


app = Flask(__name__)
app.config.from_object('settings')
# app.config.from_envvar('APP_SETTINGS')

DEFAULT_VALUE['client_id'] = app.config['CLIENT_ID']
DEFAULT_VALUE['client_secret'] = app.config['CLIENT_SECRET']
DEFAULT_VALUE['redirect_uris'] = [app.config['REDIRECT_URI']]
# DEFAULT_VALUE['behaviour'] = {
#     'response_types': ['code'],
#     'scope': ['openid', 'profile', 'email'],
#     'token_endpoint_auth_method': ['client_secret_basic', 'client_secret_post'],
# }
BEHAVIOUR_ARGS = {
    'response_types': ['code'],
    'scope': ['openid', 'profile', 'email'],
    'token_endpoint_auth_method': ['client_secret_basic', 'client_secret_post'],
}
BASE_URL = f"{app.config['PREFERRED_URL_SCHEME']}://app.config['SERVER_NAME']"
RPH = RPHandler(BASE_URL, verify_ssl=False)


@app.route("/")
def root():
    return render_template('index.html')


@app.route("/login")
def login():
    info = RPH.begin(app.config['ISSUER_ID'], behaviour_args=BEHAVIOUR_ARGS)
    session['state'] = info['state']

    return redirect(info['url'])


@app.route("/callback")
def callback():
    import sys
    from pprint import pprint

    state_key = request.args['state']
    assert request.args['state'] == session['state'], f"{state_key=} - {session['state']=}"
    # rph = RPHandler(BASE_URL)
    print('---', file=sys.stderr)
    print('REQ ARGS:', file=sys.stderr)
    pprint(request.args, stream=sys.stderr)
    session_info = RPH.get_session_information(request.args['state'])
    print('SESSION INFO:', file=sys.stderr)
    pprint(session_info, stream=sys.stderr)
    print('---', file=sys.stderr)
    res = RPH.finalize(session_info['iss'], request.args)
    print('RES:', file=sys.stderr)
    pprint(res, stream=sys.stderr)
    res['id_token'] = res.pop('id_token').to_json()
    res['userinfo'] = res.pop('userinfo').to_json()

    return jsonify(res)
    # return 'Done.'
