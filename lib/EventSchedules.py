"""

"""
#pylint: disable=W0312
import itertools
from copy import copy

class EventSchedules(object):
	def __init__(self,
				 users,
				 user_availability,
				 instructor_availability
				 ):
		self.num_users = len(users)
		self.users = users
		self.user_availability = user_availability
		self.instructor_availability = instructor_availability

	def generate_matrix(self):
		matrix = []

		num_slots = len(self.instructor_availability)

		for user in range(self.num_users):
			matrix.append([0] * num_slots)
		  
		for user_slot in matrix:
			for event in self.user_availability:
				try:
					matrix[self.users.index(event[0])][self.instructor_availability.index(event[1])] = 1
				except ValueError:
					continue

		return matrix

	def __generate_calendars_recursively(self,
										 start_index,
										 finished):
		if not self.matrix[start_index:]:
			return finished

		new_finished = copy(finished)

		for time_slot_index, time_slot in enumerate(self.matrix[start_index:][0]):
			if(time_slot == 1 and
				time_slot_index not in finished and
				start_index not in finished.values()):

				new_finished[time_slot_index] = start_index
				self.__generate_calendars_recursively(start_index + 1, new_finished)
				
				if len(new_finished) == self.num_users:
					self.all_calendars.append(copy(new_finished))
					
				del new_finished[time_slot_index]

		return new_finished

	def generate_all_calendars(self):
		self.all_calendars = []
		self.matrix = self.generate_matrix()

		self.__generate_calendars_recursively(0, {})

		return self.all_calendars
