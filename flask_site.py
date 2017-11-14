"""
Flask application for creating/handling address books.
"""
#pylint: disable=broad-except
import json
import logging
import sys
import re
import copy
from urllib.parse import urlparse, urljoin, quote_plus, unquote_plus


# OAuth2  - Google library implementation for convenience
from oauth2client import client
import httplib2   # used in oauth2 flow

import arrow
from dateutil import tz

# Google API for services 
from apiclient import discovery


# For CSV writing
from lib.CSVAddressBook import CSVAddressBook

from lib.MongoAddressClient import MongoAddressClient
from lib.Security import SecureCipher

from lib.secrets import admin_secrets
import CONFIG
import flask

from flask import redirect, request, url_for, jsonify, make_response

try:
    MONGO_CLIENT = MongoAddressClient(database_name='meeting_planner')
except Exception as exception:
    print(exception)
    print("Failure opening database. Is Mongo running? Correct password?")
    sys.exit(1)

CIPHER = SecureCipher(CONFIG.cipher_key)
SCOPES_MODIFY = 'https://www.googleapis.com/auth/calendar'
SCOPES_READONLY = 'https://www.googleapis.com/auth/calendar.readonly'
CLIENT_SECRET_FILE = admin_secrets.google_key_file

APP = flask.Flask(__name__)
APP.secret_key = CONFIG.secret_key

##############################
#
#   Special Functions
#
##############################
def is_logged_in():
    return 'id' in flask.session and flask.session['id']

def is_admin():
    return 'is_admin' in flask.session and \
        flask.session['is_admin'] is True

def is_instructor():
    return is_logged_in and \
        'is_instructor' in flask.session and \
        flask.session['is_instructor'] is True

@APP.before_request
def before_request_handler():
    """Special handler that is processed before a request is processed.
    """
    flask.g.error = flask.session['error'] if 'error' in flask.session else None
    flask.session['error'] = None

    flask.g.is_logged_in = is_logged_in()


##############################
#
#   Page Functions
#
##############################
@APP.route("/", methods=["GET"])
@APP.route("/index", methods=["GET"])
@APP.route("/home", methods=["GET"])
def index(error=None):
    """Serve the index.html page which requires a user to login to an existing address book or
    create a new one.

    """
    #MONGO_CLIENT.add_instructor(username="instructor", password="password", is_admin=1)

    flask.g.error = request.args.get('error') if 'error' in request.args else None

    if is_logged_in():
        meetings = MONGO_CLIENT.get_all_meetings(registered_id=flask.session['id'])
        meetings = [] if meetings is None else meetings

        for meeting in meetings:
            meeting['hash'] = quote_plus(CIPHER.encrypt(str(meeting['_id'])))

        flask.g.meetings = meetings

        flask.g.account_type = "instructor" if is_instructor() else "user"

    return flask.render_template('index.html')

@APP.route("/logout")
def logout():
    """Serve the index.html page which requires a user to login to an existing address book or
    create a new one.

    """
    if not is_logged_in():
        return redirect(url_for('index', error="You are already logged out!"))

    flask.session.clear()

    return redirect(url_for('index'))


@APP.route("/meeting/<meeting_hash>", methods=["GET"])
def meeting_planner(meeting_hash):
    """Serve the address_book.html page

    Args:
        address_hash (str): A hash composed of an address book's name and password.
    """
    if not is_logged_in():
        return redirect(url_for('index', error="You are not logged in!"))

    meeting_id = CIPHER.decrypt(unquote_plus(meeting_hash))
    meeting = MONGO_CLIENT.get_meeting(meeting_id=meeting_id)
    if not meeting:
        return redirect(url_for('index', error="You are not allowed to access this!"))

    flask.session['callbackURL'] = 'arranger'
    flask.session['callback_url'] = request.url

    if valid_oauth2_credentials():
        gcal_service = get_gcal_service(valid_oauth2_credentials())
        flask.session['calendarList'] = list_calendars(gcal_service)
        flask.g.calendars = flask.session['calendarList']

        primary_email = ""
        for dic in flask.session['calendarList']:
            if 'primary' in dic and dic['primary'] == True:
                primary_email = dic['id']
                break
        flask.session['primaryEmail'] = primary_email

    flask.g.meeting = meeting
    flask.g.meeting_hash = meeting_hash

    if is_instructor():
        all_users = MONGO_CLIENT.get_users(username_regex=".*")
        flask.g.possible_users = all_users

        calendar_data = MONGO_CLIENT.get_calendar_data(meeting_id=meeting_id)
        for calendar in calendar_data:
            # FIXME: can't use `get_user_username` because we can't tell the difference between instructor calendars
            # and user calendars
            calendar['username'] = MONGO_CLIENT.get_user_username(user_id=calendar['registered_id'])
        flask.g.calendar_data = calendar_data

        return flask.render_template('instructor_meeting_planner.html')
    else:
        return flask.render_template('user_meeting_planner.html')

@APP.route('/_select_calendars', methods=['POST'])
def select_calendars():
    if 'meeting_planner_hash' not in request.form:
        return jsonify(error=True,
                       message="Invalid submission.")

    meeting_id = request.form['meeting_planner_hash']
    meeting = MONGO_CLIENT.get_meeting(meeting_id=meeting_id)

    if not meeting:
        return jsonify(error=True,
                       message="Invalid submission.")

    credentials = valid_oauth2_credentials()
    if not credentials:
        return flask.redirect(flask.url_for('oauth2callback'))

    gcal_service = get_gcal_service(credentials)

    begin_time = arrow.get(interpret_time("8am"))
    end_time = arrow.get(interpret_time("5pm"))

    now = arrow.now('local')
    tomorrow = now.replace(days=+1)
    nextweek = now.replace(days=+7)
    flask.session["begin_date"] = tomorrow.floor('day').isoformat()
    flask.session["end_date"] = nextweek.ceil('day').isoformat()

    free_times = []
    databaseEntry = []
    for calendar in request.form.getlist('calendarList[]'):
        eventList = gcal_service.events().list(
            calendarId=calendar,
            timeMin=arrow.get(flask.session['begin_date']).replace(hour=begin_time.hour,
                                                                   minute=begin_time.minute).isoformat(),
            timeMax=arrow.get(flask.session['end_date']).replace(hour=end_time.hour,
                                                                 minute=end_time.minute),
            singleEvents=True,
            orderBy='startTime').execute()

        for item in eventList['items']:
            if('transparency' not in item or
               item['transparency'] != 'transparent'):
                continue

            if 'dateTime' not in item['start']:
                item['start']['dateTime'] = \
                    arrow.get(item['start']['date']).replace(hour=0,
                                                             minute=0).isoformat()
            if 'dateTime' not in item['end']:
                item['end']['dateTime'] = \
                    arrow.get(item['end']['date']).replace(days=-1,
                                                           hour=23,
                                                           minute=59).isoformat()

            item_start = arrow.get(item['start']['dateTime'])
            item_end = arrow.get(item['end']['dateTime'])
            begin_date = arrow.get(item_start).replace(hour=begin_time.hour,
                                                       minute=begin_time.minute)
            end_date = arrow.get(item_end).replace(hour=end_time.hour, minute=end_time.minute)
            if item_end <= begin_date or item_start >= end_date:
                continue

            to_append = {
                'start': item['start']['dateTime'],
                'end': item['end']['dateTime']
            }
            databaseEntry.append(copy.copy(to_append))

            to_append['summary'] = item['summary'] if 'summary' in item else ''
            to_append['calendar'] = eventList['summary']
            #toAppend['formattedDate'] = formatDates(arrow.get(toAppend['start']).isoformat(), arrow.get(toAppend['end']).isoformat())
            free_times.append(to_append)

    free_times = sorted(free_times, key=lambda k: k['start'])
    #fullAgenda = agenda(flask.session['begin_date'], flask.session['end_date'], flask.session['begin_time'], flask.session['end_time'], busyTimes)
    #flask.g.busyEvents = fullAgenda
    flask.session['free_times'] = databaseEntry


    MONGO_CLIENT.update_calendar_times(meeting_id,
                                       flask.session['id'],
                                       free_times)

    return flask.redirect(flask.session['callback_url'])


@APP.route("/_user_create_account", methods=["POST"])
def user_create_account():
    """POST handler for creating a new address book.

    """
    if('username' not in request.form or
       'password' not in request.form or
       'password_confirm' not in request.form):

        return jsonify(error=True,
                       message="Invalid submission.")

    if not request.form['password'].strip():
        return jsonify(error=True,
                       message="You must enter a non-empty password!")

    if request.form['password'] != request.form['password_confirm']:
        return jsonify(error=True,
                       message="Passwords do not match!")

    if not MONGO_CLIENT.is_username_available(register_type="user",
                                              username=request.form['username']):
        return jsonify(error=True,
                       message="That username is already registered!")

    user_id = MONGO_CLIENT.add_user(username=request.form['username'],
                                    password=request.form['password'])

    flask.session['id'] = user_id
    flask.session['is_user'] = True

    return jsonify(redirect=url_for('index'))


@APP.route("/_user_login", methods=["POST"])
def user_login():
    """POST handler for logging into an existing address book.

    Returns:
        Redirects to the respective /address_book/<address_hash> page if the credentials were valid,
        else redirects to index.
    """
    if('username' not in request.form or
       'password' not in request.form):
        return jsonify(error=True,
                       message="Invalid submission.")

    user_data = MONGO_CLIENT.get_user(username=request.form['username'],
                                      password=request.form['password'])

    if user_data is None:
        return jsonify(error=True,
                       message="The user credentials were invalid.")

    flask.session['id'] = str(user_data['_id'])
    flask.session['is_user'] = True

    return jsonify(redirect=url_for('index'))


@APP.route("/_instructor_login", methods=["POST"])
def instructor_login():
    """POST handler for logging into an existing address book.

    Returns:
        Redirects to the respective /address_book/<address_hash> page if the credentials were valid,
        else redirects to index.
    """
    if('username' not in request.form or
       'password' not in request.form):
        return jsonify(error=True,
                       message="Invalid submission.")

    instructor_data = MONGO_CLIENT.get_instructor(username=request.form['username'],
                                                  password=request.form['password'])

    if instructor_data is None:
        return jsonify(error=True,
                       message="The instructor credentials were invalid.")

    flask.session['id'] = str(instructor_data['_id'])
    flask.session['is_instructor'] = True
    flask.session['is_admin'] = instructor_data['is_admin']

    return jsonify(redirect=url_for('index'))


@APP.route("/_update_meeting_participants", methods=["POST"])
def update_meeting_participants():
    """POST handler for updating an address book's list of entries.


    """
    if not is_logged_in() or not is_instructor():
        return jsonify(redirect=url_for('index'))

    if 'meeting_planner_hash' not in request.form:
        return jsonify(error=True,
                       message="Invalid submission.")

    meeting_id = request.form['meeting_planner_hash']
    meeting = MONGO_CLIENT.get_meeting(meeting_id=meeting_id)

    if not meeting:
        return jsonify(error=True,
                       message="Invalid submission.")

    new_participants_list = []
    for participant in request.form.getlist('meeting_participants[]'):
        user_id = MONGO_CLIENT.get_user_id(username=participant)
        if user_id is None:
            continue

        if user_id not in meeting["participants"]:
            user_id = MONGO_CLIENT.get_user_id(username=participant)
            if user_id is None:
                continue

            MONGO_CLIENT.add_user_to_meeting(user_id=user_id,
                                             meeting_id=meeting_id)
        else:
            new_participants_list.append(user_id)

    for participant_id in meeting["participants"]:
        if participant_id not in new_participants_list:
            MONGO_CLIENT.remove_meeting_for_user(participant_id,
                                                 meeting_id)

    return jsonify(message="Your list of meeting participants has been updated!")



@APP.route("/_update_meeting_list", methods=["POST"])
def update_address_books():
    """POST handler for updating an address book's list of entries.


    """
    if not is_logged_in() or not is_instructor():
        return jsonify(redirect=url_for('index'))

    if 'meeting_list' not in request.form:
        return jsonify(error=True,
                       message="Invalid submission.")

    existing_meetings = MONGO_CLIENT.get_meetings_list(registered_id=flask.session['id'])
    update_meeting_list = {}
    for row in json.loads(request.form.get('meeting_list')):
        if len(row) == 1:
            MONGO_CLIENT.add_meeting(name=row[0],
                                     description="",
                                     instructor_id=flask.session['id'],
                                     participants=[])

        else:
            meeting_id = CIPHER.decrypt(unquote_plus(row[1]))
            update_meeting_list[meeting_id] = {
                "name": row[0],
                "description": ""
            }

    for meeting_id in existing_meetings:
        if meeting_id in update_meeting_list:
            meeting = update_meeting_list[meeting_id]
            MONGO_CLIENT.update_meeting(meeting_id=meeting_id,
                                        name=meeting["name"],
                                        description=meeting["description"],
                                        participants=None)
        else:
            MONGO_CLIENT.remove_meeting(meeting_id=meeting_id)

    return jsonify(redirect=url_for('index'))


@APP.route("/_get_user_calendars", methods=["POST"])
def get_user_calendars():
    credentials = valid_oauth2_credentials()
    if not credentials:
        if('callbackURL' not in flask.session or
           'callbackURL' in flask.session and flask.session['callbackURL'] == 'arranger'):
            return flask.redirect(flask.url_for('oauth2callback'))
    else:
        return flask.redirect(flask.url_for('oauth2callback', scopeType=SCOPES_MODIFY))

    gcal_service = get_gcal_service(credentials)

    flask.session['calendarList'] = list_calendars(gcal_service)
    flask.g.calendars = flask.session['calendarList']
    
    primaryEmail = ""
    for dic in flask.session['calendarList']:
        if 'primary' in dic and dic['primary'] == True:
            primaryEmail = dic['id']
            break
    flask.session['primaryEmail'] = primaryEmail
    
    if 'callbackURL' in flask.session and flask.session['callbackURL'] == 'arranger':
        return flask.redirect(flask.url_for('arranger', proposalID=flask.session['arranger']['id']))
    else:
        return flask.redirect(flask.url_for('index'))
    #return render_template('index.html')


def valid_oauth2_credentials():
    if 'credentials' not in flask.session:
        return None

    credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])

    if(credentials.invalid or
       credentials.access_token_expired):
        return None

    return credentials



def get_gcal_service(credentials):
  """
  We need a Google calendar 'service' object to obtain
  list of calendars, busy times, etc.  This requires
  authorization. If authorization is already in effect,
  we'll just return with the authorization. Otherwise,
  control flow will be interrupted by authorization, and we'll
  end up redirected back to /choose *without a service object*.
  Then the second call will succeed without additional authorization.
  """
  http_auth = credentials.authorize(httplib2.Http())
  service = discovery.build('calendar', 'v3', http=http_auth)
  return service

@APP.route('/oauth2callback')
def oauth2callback(scopeType=SCOPES_READONLY):
    """
    The 'flow' has this one place to call back to.  We'll enter here
    more than once as steps in the flow are completed, and need to keep
    track of how far we've gotten. The first time we'll do the first
    step, the second time we'll skip the first step and do the second,
    and so on.
    """
    flow =  client.flow_from_clientsecrets(
        CLIENT_SECRET_FILE,
        scope= SCOPES_MODIFY,
        redirect_uri=flask.url_for('oauth2callback', _external=True))
    ## Note we are *not* redirecting above.  We are noting *where*
    ## we will redirect to, which is this function. 

    ## The *second* time we enter here, it's a callback 
    ## with 'code' set in the URL parameter.  If we don't
    ## see that, it must be the first time through, so we
    ## need to do step 1. 
    if 'code' not in flask.request.args:
        auth_uri = flow.step1_get_authorize_url()
        return flask.redirect(auth_uri)
    ## This will redirect back here, but the second time through
    ## we'll have the 'code' parameter set
    else:
        ## It's the second time through ... we can tell because
        ## we got the 'code' argument in the URL.
        auth_code = flask.request.args.get('code')
        credentials = flow.step2_exchange(auth_code)
        flask.session['credentials'] = credentials.to_json()
        ## Now I can build the service and execute the query,
        ## but for the moment I'll just log it and go back to
        ## the main screen
        return flask.redirect(flask.session['callback_url'])

##############################
#
#   Helper Functions
#
##############################
def interpret_time( text ):
    """
    Read time in a human-compatible format and
    interpret as ISO format with local timezone.
    May throw exception if time can't be interpreted. In that
    case it will also flash a message explaining accepted formats.
    """
    time_formats = ["ha", "h:mma",  "h:mm a", "H:mm"]
    try: 
        as_arrow = arrow.get(text, time_formats).replace(tzinfo=tz.tzlocal())
        as_arrow = as_arrow.replace(year=2016)
    except:
        flask.flash("Time '{}' didn't match accepted formats 13:30 or 1:30pm"
              .format(text))
        raise
    return as_arrow.isoformat()

def list_calendars(service):
    """
    Given a google 'service' object, return a list of
    calendars.  Each calendar is represented by a dict.
    The returned list is sorted to have
    the primary calendar first, and selected (that is, displayed in
    Google Calendars web app) calendars before unselected calendars.
    """
    calendar_list = service.calendarList().list().execute()["items"]
    result = [ ]
    for cal in calendar_list:
        kind = cal["kind"]
        id = cal["id"]
        if "description" in cal: 
            desc = cal["description"]
        else:
            desc = "(no description)"
        summary = cal["summary"]
        # Optional binary attributes with False as default
        selected = ("selected" in cal) and cal["selected"]
        primary = ("primary" in cal) and cal["primary"]
        

        result.append(
          { "kind": kind,
            "id": id,
            "summary": summary,
            "selected": selected,
            "primary": primary
            })
    return sorted(result, key=cal_sort_key)

def cal_sort_key( cal ):
    """
    Sort key for the list of calendars:  primary calendar first,
    then other selected calendars, then unselected calendars.
    (" " sorts before "X", and tuples are compared piecewise)
    """
    if cal["selected"]:
       selected_key = " "
    else:
       selected_key = "X"
    if cal["primary"]:
       primary_key = " "
    else:
       primary_key = "X"
    return (primary_key, selected_key, cal["summary"])

def error_and_redirect(error, page):
    flask.session["error"] = error
    return redirect(page)

def is_safe_url(target):
    """Determine if a target url is considered safe.

    Args:
        target (str): The url

    Returns:
        True if safe, else False.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))

    return test_url.scheme in ('http', 'https') and \
        ref_url.netloc == test_url.netloc

def get_previous_page():
    """Return the url for the referring page.

    """
    return request.referrer if is_safe_url(request.referrer) else url_for('index')


##############################
#
#   Error Handlers
#
##############################
@APP.errorhandler(403)
def error_403(error):
    """403 error handling

    Returns:
        The 403.html page
    """
    APP.logger.warning("++ 403 error: %s", error)
    return flask.render_template('403.html'), 403

@APP.errorhandler(404)
def error_404(error):
    """404 error handling

    Returns:
        The 404.html page
    """
    APP.logger.warning("++ 404 error: %s", error)
    return flask.render_template('404.html'), 404

@APP.errorhandler(500)
def error_500(error):
    """500 error handling

    Returns:
        The 500.html page
    """
    APP.logger.warning("++ 500 error: %s", error)
    assert APP.debug is False
    return flask.render_template('500.html'), 500


if __name__ == "__main__":
    APP.debug = True
    APP.logger.setLevel(logging.DEBUG)
    APP.run(threaded=True, port=80, host="0.0.0.0")
