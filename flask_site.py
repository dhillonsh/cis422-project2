# FIXME: Users should see the instructors calendar if available
# FIXME: finalizing meetings should add events to all participant calendars (more information needs to be stored in the database to remember calendars)
# FIXME: if meeting range changes, wipe all Calendar data
# FIXME: Add `location` to calendar_data table
# FIXME: Adjust algorithm to work with arbitrary meeting length, instead of fixed 15 minutes
# FIXME: Better redirect when gcal not authenticated

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

import arrow
from dateutil import tz


from lib.MongoAddressClient import MongoAddressClient
from lib.EventSchedules import EventSchedules
from lib.Security import SecureCipher
from lib.GoogleAPIService import GoogleAPIService

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
GoogleAPI = GoogleAPIService(google_key_file=admin_secrets.google_key_file)

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
    flask.g.redirect_message = flask.session['redirect_message'] if 'redirect_message' in flask.session else None
    flask.session['redirect_message'] = None

    flask.g.is_logged_in = is_logged_in()

    if('credentials' in flask.session and flask.session['credentials']):
        GoogleAPI.set_credentials(credentials=flask.session['credentials'])


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
    #MONGO_CLIENT.add_instructor(username="instructor_a", password="password", is_admin=1)

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


def generate_availability(meeting_length,
                          free_events):
    availability = []

    for free_event in free_events:
        tmp_start = arrow.get(free_event['start'], "YYYY-MM-DDTHH:mm:ssZZ")
        tmp_end = arrow.get(free_event['end'], "YYYY-MM-DDTHH:mm:ssZZ")
        while tmp_start < tmp_end:
            availability.append(tmp_start.format('YYYY-MM-DDTHH:mm:ssZZ'))
            tmp_start = tmp_start.replace(minutes=+15)

    return availability


@APP.route("/meeting/<meeting_hash>", methods=["GET", "POST"])
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


    flask.g.meeting = meeting
    flask.g.meeting_hash = meeting_hash

    meeting_owner = MONGO_CLIENT.get_meeting_owner(meeting_id=meeting_id)
    instructor_calendar = MONGO_CLIENT.get_calendar_data(registered_id=meeting_owner,
                                                         meeting_id=meeting_id)

    flask.g.my_calendar = MONGO_CLIENT.get_calendar_data(registered_id=flask.session['id'],
                                                         meeting_id=meeting_id)

    flask.g.instructor_calendar = instructor_calendar

    if flask.request.method == 'POST':
        calendar_data = MONGO_CLIENT.get_all_calendar_data(meeting_id=meeting_id)


        instructor_availability = generate_availability(meeting_length=15,
                                                        free_events=instructor_calendar['free_times'])


        users = []
        user_availability = []
        for calendar in calendar_data[:]:
            # Instructors calendar, remove it from list
            if calendar['registered_id'] == flask.session['id']:
                continue

            users.append(calendar['registered_id'])

            for free_event in calendar['free_times']:
                tmp_start = arrow.get(free_event['start'], "YYYY-MM-DDTHH:mm:ssZZ")
                tmp_end = arrow.get(free_event['end'], "YYYY-MM-DDTHH:mm:ssZZ")
                while tmp_start < tmp_end:
                    user_availability.append([calendar['registered_id'], tmp_start.format('YYYY-MM-DDTHH:mm:ssZZ')])
                    tmp_start = tmp_start.replace(minutes=+15)


        all_calendars = EventSchedules(users=users,
                                       user_availability=user_availability,
                                       instructor_availability=instructor_availability)

        flask.g.instructor_availability = instructor_availability
        flask.g.user_availability = user_availability
        flask.g.all_calendars = all_calendars.generate_all_calendars()

    flask.session['callbackURL'] = 'arranger'
    flask.session['callback_url'] = request.url

    if GoogleAPI.is_verified():
        flask.session['calendarList'] = GoogleAPI.get_all_calendars()
        flask.g.calendars = flask.session['calendarList']

        primary_email = ""
        for dic in flask.session['calendarList']:
            if 'primary' in dic and dic['primary'] == True:
                primary_email = dic['id']
                break
        flask.session['primaryEmail'] = primary_email

    if is_instructor():
        id_to_username_map = {}

        all_users = MONGO_CLIENT.get_users(username_regex=".*")
        
        awaiting_participants = copy.copy(meeting['participants'])

        calendar_data = MONGO_CLIENT.get_all_calendar_data(meeting_id=meeting_id)
        for calendar in calendar_data[:]:
            # Instructors calendar, remove it from list
            if calendar['registered_id'] == flask.session['id']:
                calendar_data.remove(calendar)
                break

        for calendar in calendar_data:
            calendar['username'] = MONGO_CLIENT.get_user_username(user_id=calendar['registered_id'])
            awaiting_participants.remove(calendar['registered_id'])
            
        for participant in meeting['participants']:
            id_to_username_map[participant] = MONGO_CLIENT.get_user_username(user_id=participant)

        flask.g.awaiting_participants = awaiting_participants
        flask.g.id_to_username_map = id_to_username_map
        flask.g.calendar_data = calendar_data
        flask.g.possible_users = all_users

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

    if not GoogleAPI.is_verified():
        return flask.redirect(flask.url_for('oauth2callback'))

    begin_time = arrow.get(interpret_time("00:00"))
    end_time = arrow.get(interpret_time("23:59"))

    meeting_begin_date = interpret_date(meeting['meeting_start'])
    meeting_end_date = interpret_date(meeting['meeting_end'])

    free_times = []
    databaseEntry = []
    for calendar in request.form.getlist('calendarList[]'):
        eventList = GoogleAPI.get_all_events(calendar=calendar,
                                             date_start=arrow.get(meeting_begin_date).replace(hour=begin_time.hour,
                                                          minute=begin_time.minute).isoformat(),
                                             date_end=arrow.get(meeting_end_date).replace(hour=end_time.hour,
                                                        minute=end_time.minute))

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
            test_date = arrow.get(item_start).replace(hour=begin_time.hour,
                                                       minute=begin_time.minute)
            end_date = arrow.get(item_end).replace(hour=end_time.hour, minute=end_time.minute)
            if item_end <= test_date or item_start >= end_date:
                continue

            to_append = {
                'start': item['start']['dateTime'],
                'end': item['end']['dateTime']
            }
            databaseEntry.append(copy.copy(to_append))

            to_append['summary'] = item['summary'] if 'summary' in item else ''
            to_append['calendar'] = eventList['summary']
            free_times.append(to_append)

    free_times = sorted(free_times, key=lambda k: k['start'])

    MONGO_CLIENT.update_calendar_times(meeting_id=meeting_id,
                                       registered_id=flask.session['id'],
                                       email=flask.session['primaryEmail'],
                                       free_times=free_times)

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


@APP.route("/_update_meeting_info", methods=["POST"])
def update_meeting_info():
    """


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

    if('meeting_description' not in request.form or
       'meeting_start' not in request.form or
       'meeting_end' not in request.form):
        return jsonify(error=True,
                       message="Invalid submission.")

    new_description = request.form['meeting_description']
    MONGO_CLIENT.update_meeting_description(meeting_id=meeting_id,
                                            description=new_description
                                            )

    meeting_start = request.form['meeting_start']
    meeting_end = request.form['meeting_end']
    MONGO_CLIENT.update_meeting_range(meeting_id=meeting_id,
                                      meeting_start=meeting_start,
                                      meeting_end=meeting_end
                                     )

    return jsonify(redirect=url_for('meeting_planner', meeting_hash=request.form['meeting_planner_hash']))



@APP.route("/_finalize_meeting", methods=["POST"])
def finalize_meeting():
    """


    """
    if not is_logged_in() or not is_instructor():
        return jsonify(redirect=url_for('index'))

    if('meeting_planner_hash' not in request.form or
       'calendar_events' not in request.form):
        return jsonify(error=True,
                       message="Invalid submission.")

    meeting_id = request.form['meeting_planner_hash']
    meeting = MONGO_CLIENT.get_meeting(meeting_id=meeting_id)
    meeting['location'] = 'default' # FIXME: MAKE A VARIABLE IN DB

    if not meeting:
        return jsonify(error=True,
                       message="Invalid submission.")

    try:
        calendar_events = json.loads(request.form.get('calendar_events'));
    except Exception:
        return jsonify(error=True,
                       message="Invalid calendar data.")

    # FIXME: Better redirect when gcal not authenticated
    if not GoogleAPI.is_verified():
        return redirect(url_for('oauth2callback'))

    meeting_owner = MONGO_CLIENT.get_meeting_owner(meeting_id=meeting_id)
    instructor_calendar = MONGO_CLIENT.get_calendar_data(registered_id=meeting_owner,
                                                         meeting_id=meeting_id)

    calendar_data = MONGO_CLIENT.get_all_calendar_data(meeting_id=meeting_id)


    meeting_times = {}
    for calendar_event in calendar_events:
        meeting_times[calendar_event['id']] = {
            "start": calendar_event['start'],
            "end": calendar_event['end']
        }

    for calendar in calendar_data[:]:
        if(calendar['registered_id'] not in meeting_times):
            continue

        email_list = []
        email_list.append({
            'email': instructor_calendar['email']
        })
        email_list.append({
            'email': calendar['email']
        })

        meeting_start = arrow.get(meeting_times[calendar['registered_id']]['start']).replace(tzinfo=tz.tzlocal())
        meeting_end = arrow.get(meeting_times[calendar['registered_id']]['end']).replace(tzinfo=tz.tzlocal())

        GoogleAPI.create_event(summary=meeting["name"],
                               location=meeting["location"],
                               description=meeting["description"],
                               start=meeting_start.isoformat(),
                               end=meeting_end.isoformat(),
                               attendees=email_list)

        flask.session['redirect_message'] = {
            "message": "Your meetings have been scheduled."
        }

    return jsonify(redirect=url_for('meeting_planner', meeting_hash=request.form['meeting_planner_hash']))


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
        return flask.redirect(flask.url_for('oauth2callback', scopeType=GoogleAPI.SCOPES_MODIFY))

    flask.session['calendarList'] = GoogleAPI.get_all_calendars()
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

    credentials = GoogleAPI.get_oauth2_credentials()

    if(credentials.invalid or
       credentials.access_token_expired):
        return None

    return credentials


@APP.route('/oauth2callback')
def oauth2callback(scopeType=GoogleAPI.SCOPES_READONLY):
    """
    The 'flow' has this one place to call back to.  We'll enter here
    more than once as steps in the flow are completed, and need to keep
    track of how far we've gotten. The first time we'll do the first
    step, the second time we'll skip the first step and do the second,
    and so on.
    """
    if 'code' not in flask.request.args:
        return flask.redirect(GoogleAPI.get_auth_uri(redirect_uri=flask.url_for('oauth2callback',
                                                                                _external=True)))
    else:
        auth_code = flask.request.args.get('code')

        flask.session['credentials'] = GoogleAPI.get_credentials(
            redirect_uri=flask.url_for('oauth2callback',
                                       _external=True),
            auth_code=auth_code)

        return flask.redirect(flask.session['callback_url'])

##############################
#
#   Helper Functions
#
##############################
def interpret_date(text):
    """
    Convert text of date to ISO format used internally,
    with the local time zone.
    """
    try:
      as_arrow = arrow.get(text, "MM/DD/YYYY").replace(
          tzinfo=tz.tzlocal())
    except:
        flask.flash("Date '{}' didn't fit expected format 12/31/2001")
        raise
    return as_arrow.isoformat()

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
