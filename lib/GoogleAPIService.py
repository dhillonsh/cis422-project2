from apiclient import discovery
from oauth2client import client
import httplib2

class GoogleAPIService(object):
	SCOPES_MODIFY = 'https://www.googleapis.com/auth/calendar'
	SCOPES_READONLY = 'https://www.googleapis.com/auth/calendar.readonly'
	credentials_json = None

	def __init__(self,
				 google_key_file):
		self.google_key_file = google_key_file

	def is_verified(self):
		return True if self.get_oauth2_credentials() is not None else False

	def create_event(self,
					 summary,
                     location,
                     description,
                     start,
                     end,
                     attendees):
		gcal_service = self.get_gcal_service()
		if not gcal_service:
			return None

		event = {
			'summary': summary,
			'location': location,
			'description': description,
			'start': {
				'dateTime': start
			},
			'end': {
				'dateTime': end
			},
			'attendees': attendees
		}

		gcal_service.events().insert(calendarId='primary',
									 sendNotifications=True,
									 body=event).execute()

	def get_all_events(self,
					   calendar,
					   date_start,
					   date_end):
		gcal_service = self.get_gcal_service()
		if not gcal_service:
			return None

		return gcal_service.events().list(
			calendarId=calendar,
			timeMin=date_start,
			timeMax=date_end,
			singleEvents=True,
			orderBy='startTime').execute()

	def get_all_calendars(self):
		"""
		Given a google 'service' object, return a list of
		calendars.  Each calendar is represented by a dict.
		The returned list is sorted to have
		the primary calendar first, and selected (that is, displayed in
		Google Calendars web app) calendars before unselected calendars.
		"""
		gcal_service = self.get_gcal_service()
		if not gcal_service:
			return None

		calendar_list = gcal_service.calendarList().list().execute()["items"]
		result = [ ]
		for cal in calendar_list:
			kind = cal["kind"]
			id = cal["id"]
			if "description" in cal: 
				desc = cal["description"]
			else:
				desc = "(no description)"
			summary = cal["summary"]
			selected = ("selected" in cal) and cal["selected"]
			primary = ("primary" in cal) and cal["primary"]
			

			result.append({
				"kind": kind,
				"id": id,
				"summary": summary,
				"selected": selected,
				"primary": primary
			})
		return sorted(result, key=self.__calendar_sort)

	def set_credentials(self,
						credentials):
		self.credentials_json = credentials

	def get_gcal_service(self):
		"""
		We need a Google calendar 'service' object to obtain
		list of calendars, busy times, etc.  This requires
		authorization. If authorization is already in effect,
		we'll just return with the authorization. Otherwise,
		control flow will be interrupted by authorization, and we'll
		end up redirected back to /choose *without a service object*.
		Then the second call will succeed without additional authorization.
		"""
		credentials = self.get_oauth2_credentials()
		if not credentials:
			return None

		http_auth = credentials.authorize(httplib2.Http())
		service = discovery.build('calendar', 'v3', http=http_auth)
		return service

	def get_oauth2_credentials(self):
		if not self.credentials_json:
			return None

		credentials = client.OAuth2Credentials.from_json(self.credentials_json)

		if(credentials.invalid or
		   credentials.access_token_expired):
			return None

		return credentials

	def get_flow(self,
				 redirect_uri):
		return 	client.flow_from_clientsecrets(
			self.google_key_file,
			scope=self.SCOPES_MODIFY,
			redirect_uri=redirect_uri)

	def get_auth_uri(self,
					 redirect_uri):

		flow = self.get_flow(redirect_uri=redirect_uri)

		return flow.step1_get_authorize_url()

	def get_credentials(self,
						redirect_uri,
						auth_code):

		flow = self.get_flow(redirect_uri=redirect_uri)

		credentials = flow.step2_exchange(auth_code)
		return credentials.to_json()

	def __calendar_sort(self,
						calendar):
		"""
		Sort key for the list of calendars:  primary calendar first,
		then other selected calendars, then unselected calendars.
		(" " sorts before "X", and tuples are compared piecewise)
		"""
		selected_key = " " if calendar["selected"] else "X"
		primary_key = " " if calendar["primary"] else "X"

		return (primary_key, selected_key, calendar["summary"])
