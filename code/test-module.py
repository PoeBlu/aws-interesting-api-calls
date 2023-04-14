#!/usr/bin/env python3

import yaml
from pprint import pprint
from InterestingAwsActions import *
from sys import argv

if len(argv) < 2:
    filename = "https://raw.githubusercontent.com/jchrisfarris/aws-interesting-api-calls/master/actions.yaml"
else:
    filename = argv[1]

try:
    action_db = ActionDatabase(filename)
    # action_db = ActionDatabase("https://raw.githubusercontent.com/jchrisfarris/aws-interesting-api-calls/master/actions.yaml")
except ActionFileParseError as e:
    print(e)
    print("Aborting....")
    exit(1)
except NotImplementedError as e:
    print(e)
    print("Aborting....")
    exit(1)

print(f"Services: {action_db.list_services()}")
print(f"Severities: {action_db.list_severities()}")
print(f"Categories: {action_db.list_categories()}")
print(f"Risk Types: {action_db.list_risks()}")

print(f'All AccessControl Calls: {action_db.by_category("AccessControl")}')

print(
    f'API Calls resulting in AccountTakeOver: {action_db.by_risk("AccountTakeOver")}'
)

print("----------------------\n\n")

try: 
    action = action_db.get_action("organizations:DeletePolicy")
    pprint(action.__dict__)
    print(action.URL)
except ActionLookupError as e:
    print(e)


print("----------------------\n\n")


high = action_db.by_severity("high")
print(f"Got {len(high)} high severity actions")
for name in high:
    a = action_db.get_action(name)
    print(f"{name}\t\t{a.Description}")
print("----------------------\n\n")


ec2 = action_db.by_service('ec2')
print(f"Got {len(ec2)} ec2 actions")
for name in ec2:
    a = action_db.get_action(name)
    print(f"{name}\t\t{a.Description}")

print("----------------------\n\n")
print("Summary Report:")
for service in action_db.list_services():
    print(f"Service {service} has {len(action_db.by_service(service))} actions")

for severity in action_db.list_severities():
    print(
        f"Severity {severity} has {len(action_db.by_severity(severity))} actions"
    )

for category in action_db.list_categories():
    print(
        f"Category {category} has {len(action_db.by_category(category))} actions"
    )

for risk in action_db.list_risks():
    print(f"Risk {risk} has {len(action_db.by_risk(risk))} actions")


