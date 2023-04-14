

import yaml
import json
from pprint import pprint
import boto3
from botocore.exceptions import ClientError


severity_levels = {
	'critical' 	: 0,
	'high'		: 1,
	'medium'	: 3,
	'low'		: 4
}

class Action(object):
	"""Represents the API Call"""
	def __init__(self, database, action_name):
		super(Action, self).__init__()
		self.db = database
		self.name = action_name
		if action_name == "*":
			raise ActionLookupError("Action is *")
		# split the action name to get the service and api_call
		try: 
			(self.service, self.api_call) = action_name.split(':')
		except ValueError:
			raise ActionLookupError(f"Service or API Call {action_name} is not valid")
		# Load in the rest of the stuff to the namespace
		try: 
			self.__dict__.update(database.action_list[self.service][self.api_call])
		except KeyError as e:
			raise ActionLookupError(f"Service or API Call {e} is not valid")

	def is_severe(self, severity):
		'''returns true if this action's severity is greater than the one passed in'''
		try:
			return severity_levels[self.Severity] <= severity_levels[severity]
		except KeyError:
			return(False)

	def __str__(self):
		"""when converted to a string, convert to the Service:ApiCall format"""
		return(self.name)

	# I'm sure this is totally not the right python convention here. 
	def __repr__(self):
		return f"<InterestingAwsActions:Action {self.name} >"

#
#
############################################
#
#
class ActionDatabase(object):
	"""Represents the Database of Interesting API Calls"""
	def __init__(self, filename):
		"""loads the file from the local filesystem"""
		super(ActionDatabase, self).__init__()
		self.filename = filename
		if "https://" in filename or "http://" in filename:
			# raise NotImplementedError("HTTP Support not available yet")

			import requests
			r = requests.get(filename)
			if r.status_code != 200:
				raise ActionFileParseError(
					f"Got HTTP Code {r.status_code} requesting {filename}"
				)

			try: 
				self.action_list = yaml.load(r.content)
			except yaml.YAMLError as exc:
					# print(exc)
				raise ActionFileParseError(
					f"Error parsing {filename}: {exc}".replace('\n', ' ')
				)
		else: # Assume local file
			try:
				with open(filename, 'r') as stream:
					try:
						self.action_list = yaml.load(stream)
					except yaml.YAMLError as exc:
						# print(exc)
						raise ActionFileParseError(
							f"Error parsing {filename}: {exc}".replace('\n', ' ')
						)
			except IOError as e:
				raise ActionFileParseError(f"Error reading {filename}: {e}")	

	def get_action(self, action_name):
		"""Returns an Action Object """
		return(Action(self, action_name))

	def get_actions_by_service(self, service):
		"""Returns a list of Actions fitting the specific service"""
		return [f"{service}:{api_call}" for api_call in self.action_list[service]]

	def get_api_calls_by_service(self, service):
		"""Returns a list of Actions fitting the specific service"""
		return list(self.action_list[service])

	def get_actions_by_severity(self, severity):
		"""Return a list of all api_calls where Severity = <severity>"""
		return(self.__get_actions_by_key__("Severity", severity))

	def get_actions_by_severity_filter(self, severity_filter):
		output = []
		for s in severity_levels.keys():
			if severity_levels[s] <= severity_levels[severity_filter]:
				output = output + self.get_actions_by_severity(s)
		return(output)

	def get_actions_by_category(self, category):
		"""Return a list of all api_calls where Category = <category>"""
		return(self.__get_actions_by_key__("Category", category))

	def get_actions_by_risk(self, risk):
		"""Return a list of all api_calls where Risk = <risk>"""
		return(self.__get_actions_by_key__("Risk", risk))

	def __get_actions_by_key__(self, key, value):
		output = []
		for service in self.action_list:
			# print("Found Service: {}".format(service))
			output.extend(
				f"{service}:{api_call}"
				for api_call in self.action_list[service]
				if self.action_list[service][api_call][key] == value
			)
		return(output)

	def list_services(self):
		"""Returns a list of services that appear in the database"""
		return(self.action_list.keys())

	def list_severities(self):
		"""Returns a list of valid severities in the database"""
		return(self.__list_key__("Severity"))

	def list_categories(self):
		"""Returns a list of valid categories in the database"""
		return(self.__list_key__("Category"))

	def list_risks(self):
		"""Returns a list of valid risk types in the database"""
		return(self.__list_key__("Risk"))

	def __list_key__(self, key):
		""" Internal function to return a list of valid keys"""
		api_list = {}
		for service in self.action_list:
			# print("Found Service: {}".format(service))
			for api_call in self.action_list[service]:
				# print("\tFound Action: {}".format(api_call))
				value = self.action_list[service][api_call][key]

				# Added for Python2 / Python3 compat
				# https://stackoverflow.com/a/22679982
				try:
					basestring
				except NameError:
					basestring = str

				if isinstance(value, basestring):
					if value in api_list:
						api_list[value].append(api_call)
					else:
						api_list[value] = [api_call]
				else: 
					for v in value:
						if v in api_list:
							api_list[v].append(api_call)
						else:
							api_list[v] = [api_call]

		return list(api_list)



	def get_actions_by_iam_action_string(self, action_wildcard):
		"""
		Returns a list of actions that match the iam action string. 
		ex "ec2:Create*" will return ec2:CreateRoute, ec2:CreateVPC, etc.
		likewise ec2:*VPC should return ec2:DescribeVPC and ec2:CreateVPC, but not ec2:CreateVPCEndpoint
		"""
		(service, api_wildcard) = action_wildcard.split(':')
		output = []

		if '*' not in action_wildcard:
			if api_wildcard in self.get_api_calls_by_service(service):
				return([Action(self,action_wildcard)])
			else:
				return([])

		if api_wildcard == "*":
			output.extend(
				Action(self, f"{service}:{a}")
				for a in self.get_api_calls_by_service(service)
			)
		else:
			api_wildcard_substr = action_wildcard.replace("*", "")
			for a in self.get_api_calls_by_service(service):
				if api_wildcard_substr in a:
					try:
						output.append(Action(self, f"{service}:{a}"))
					except ActionLookupError:
						print(
							f"Weird. {api_wildcard_substr} is a substr of {a}, yet the Action Lookup failed"
						)
		# print("found actions for {} of {}".format(action_wildcard, output))
		return(output)

	def sort_actions_by_category(self, action_list):
		'''Given a list of iam actions, return a dict of arrays where the dict key is the action's category in the db'''
		output = {}
		for a in action_list:
			action = Action(self, a)
			if action.Category in output:
				output[action.Category].append(a)
			else:
				output[action.Category] = [a]
		return(output)


class PolicySimulator(object):
	"""execute Policy Simulations for a User/Group/Role based on the InterestingActions Database"""
	def __init__(self, action_file, creds):
		super(PolicySimulator, self).__init__()
		self.action_file = action_file
		self.creds = creds
		self.action_db = ActionDatabase(action_file)
		self.iam_client = boto3.client('iam', 		
			aws_access_key_id = creds['AccessKeyId'],
			aws_secret_access_key = creds['SecretAccessKey'],
			aws_session_token = creds['SessionToken']
		)

	def simulate_resource(self, resource_arn, severity_filter):
		'''return a list of all interesting api calls resource can execute that are higher than the severity filter'''
		output = []
		actions_of_interest = self.action_db.get_actions_by_severity_filter(severity_filter)
		try:
			response = self.iam_client.simulate_principal_policy (
				PolicySourceArn=resource_arn,
				ActionNames=actions_of_interest
			)
			while response['IsTruncated'] == "True":
				for e in response['EvaluationResults']:
					if e['EvalDecision'] != "allowed":
						continue
					output.append(e.EvalActionName)
				response = self.iam_client.simulate_principal_policy (
					PolicySourceArn=resource_arn,
					ActionNames=actions_of_interest,
					MaxItems=100, Marker=response['Marker']
				)

			for e in response['EvaluationResults']:
				if e['EvalDecision'] != "allowed":
					continue
				output.append(e['EvalActionName'])
			if len(actions_of_interest) == len(output):
				return(["Full Administrative Access"])
			else:
				return(output)
		except ClientError as e:
			print(f"Error Simulating Policy: {e}")
			exit(1)
		

class ActionFileParseError(Exception):
	'''Raised when the Action yaml file has a syntax error'''

class ActionLookupError(LookupError):
	'''Raised when the Action requested is not in the database'''		