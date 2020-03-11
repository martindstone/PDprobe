#!/usr/bin/env python

# Cron-style schedule for when to run checks against PD
# every minute:
CHECK_SCHEDULE = "* * * * *"
#
# every hour at :00:
# CHECK_SCHEDULE = "0 * * * *"
#
# every hour at :00, :15, :30, and :60:
# CHECK_SCHEDULE = "*/15 * * * *"
#
# Check out https://crontab.guru if you need help with cron expressions


import os
import time
from datetime import datetime
import requests
import pd
import json
import secrets
import threading

# for making tunnels with external URLs so we can listen for webhooks
from pyngrok import ngrok

# cron scheduler
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

# webhook listener
from flask import Flask, request
app = Flask(__name__)

def report_results(check_results):
    # This is where you would customize what to do with test results. 
    # You could send to a dashboarding system, or do further processing...
    # 
    # check_results will be a JSON structure that looks like this:
    # {
    #     "time_started": <UTC time when the test was started, in ISO8601 format>,
    #     "rest": <one of "success", "fail", "not tested">,
    #     "events": <one of "success", "fail", "not tested">,
    #     "webhooks": <one of "success", "fail", "not tested">,
    #     "errors": [an array of strings representing any errors that were encountered while testing]
    # }
    #
    # Example for a successful test:
    # {
    #     "time_started": "2020-03-10T15:11:00Z",
    #     "rest": "success",
    #     "events": "success",
    #     "webhooks": "success",
    #     "errors": []
    # }
    #
    print("PD check results:")
    print("----------------------------------")
    print(json.dumps(check_results, indent=4))
    print("----------------------------------")



@app.route('/', methods=['GET', 'POST'])
def index():
    global check_results
    token = os.environ.get('TOKEN')
    # just look for an incident.trigger event
    if request.method == 'POST':
        try:
            content = request.get_json(force=True)
            event = content['messages'][0]['event']
            service_id = content['messages'][0]['incident']['service']['id']
            service_name = content['messages'][0]['incident']['service']['name']
            print(f"got {event} on service {service_name}")
            check_results[service_name]['webhooks'] = 'success'
            teardown(service_name, token)
        except Exception as e:
            print(f"oops! {e}")
            pass
    return 'ok'

def create_escalation_policy(token, name):
    """ create an escalation policy in PD """
    users = pd.request(token=token, endpoint="users", params={"limit": 1})
    user = users['users'][0]

    body = {
        "escalation_policy": {
            "type": "escalation_policy",
            "name": name,
            "escalation_rules": [
                {
                    "escalation_delay_in_minutes": 10,
                    "targets": [
                        {
                            "id": user['id'],
                            "type": "user_reference"
                        }
                    ]
                }
            ],
            "description": "PDprobe transient"
        }
    }
    return pd.request(token=token, endpoint="escalation_policies", method="POST", data=body)

def create_service(token, name, ep_id):
    """ create a service in PD """
    body = {
        "service": {
            "type": "service",
            "name": name,
            "escalation_policy": {
                "id": ep_id,
                "type": "escalation_policy_reference"
            },
            "incident_urgency_rule": {
                "type": "constant",
                "urgency": "low"
            },
            "alert_creation": "create_alerts_and_incidents"
        }
    }
    return pd.request(token=token, endpoint="services", method="POST", data=body)

def create_integration(token, service_id):
    """ create an integration in a PD service """
    body = {
        "type": "events_api_v2_inbound_integration",
        "name": "PDprobe",
    }
    return pd.request(token=token, endpoint=f"services/{service_id}/integrations", method="POST", data=body)

def create_webhook(token, name, service_id, public_url):
    """ create a webhook in a PD service """
    body = {
        "webhook": {
            "type": "webhook_reference",
            "name": name,
            "endpoint_url": public_url,
            "webhook_object": {
                "id": service_id,
                "type": "service_reference"
            },
            "outbound_integration": {
                "id": "PJFWPEP",
                "type": "outbound_integration"
            }
        }
    }
    return pd.request(token=token, endpoint=f"webhooks", method="POST", data=body)

def send_trigger(routing_key, dedup_key):
    """ send a trigger alert """
    payload = {
        "payload": {
            "summary": f"Test {dedup_key}",
            "source": f"{dedup_key}",
            "severity": "critical",
        },
        "routing_key": routing_key,
        "dedup_key": dedup_key,
        "event_action": "trigger"
    }
    return pd.send_v2_event(payload)

def destroy_escalation_policy(token, ep_id):
    """ destroy an escalation policy in PD """
    return pd.request(token=token, endpoint=f"escalation_policies/{ep_id}", method="DELETE")

def destroy_service(token, ep_id):
    """ destroy a service in PD """
    return pd.request(token=token, endpoint=f"services/{ep_id}", method="DELETE")

def teardown(name, token):
    global checks
    global check_results
    global timers

    if check_results[name]:
        check_results[name]['time_ended'] = datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'
        if check_results[name]['events'] == 'success' and check_results[name]['webhooks'] == 'not tested':
            # we sent an event but didn't get a webhook
            check_results[name]['webhooks'] = 'fail'
            check_results[name]['errors'].append("Timed out waiting for webhook")
        report_results(check_results[name])
        del check_results[name]

    if timers[name] and isinstance(timers[name], threading.Timer):
        timers[name].cancel()
        del timers[name]

    if checks[name]:
        if checks[name]['service_id']:
            print(f"Destroying service {checks[name]['service_id']}")
            destroy_service(token, checks[name]['service_id'])
        if checks[name]['ep_id']:
            print(f"Destroying escalation policy {checks[name]['ep_id']}")
            destroy_escalation_policy(token, checks[name]['ep_id'])
        del checks[name]


def check_pd():
    """ check all the PD things """

    # make up a unique name for created objects
    name = f"PDprobe-{secrets.token_hex(32)}"
    token = os.environ.get('TOKEN')
    service_id = None
    ep_id = None

    global checks
    global check_results
    global timers

    check_results[name] = {
        'time_started': datetime.utcnow().replace(microsecond=0).isoformat() + 'Z',
        'rest': 'not tested',
        'events': 'not tested',
        'webhooks': 'not tested',
        'errors': []
    }

    try:
        # create an EP
        print(f"Creating escalation policy {name}")
        ep = create_escalation_policy(token=token, name=name)
        ep_id = ep['escalation_policy']['id']
        print(f"Created EP {ep['escalation_policy']['name']}")

        # create a service
        print(f"Creating service {name}")
        service = create_service(token=token, name=name, ep_id=ep_id)
        service_id = service['service']['id']
        print(f"Created service {service['service']['name']}")

        # add a v2 integration
        print(f"Adding integration")
        integration = create_integration(token=token, service_id=service_id)
        routing_key = integration['integration']['integration_key']
        print(f"Added integration with key {routing_key}")

        # add a webhook
        print(f"Adding webhook {name}")
        webhook = create_webhook(token, name, service_id, public_url)
        print(f"Added webhook {webhook['webhook']['name']}")

        if ep_id and service_id and routing_key:
            check_results[name]['rest'] = 'success'
            checks[name] = {
                "service_id": service_id,
                "ep_id": ep_id
            }
        else:
            check_results[name]['rest'] = 'fail'
    except Exception as e:
        check_results[name]['rest'] = 'fail'
        check_results[name]['errors'].append(str(e))

    try:
        if routing_key:
            # send an event
            print(f"Sending test alert to {routing_key}")
            trigger_response = send_trigger(routing_key=routing_key, dedup_key=name)
            if trigger_response['status'] == 'success' and trigger_response['dedup_key'] == name:
                check_results[name]['events'] = 'success'
            else:
                check_results[name]['events'] = 'fail'
                check_results[name]['errors'].append(str(trigger_response))

    except:
        check_results[name]['events'] = 'fail'

    
    # destroy everything later
    timers[name] = threading.Timer(10.0, teardown, kwargs={"name": name, "token": token})
    timers[name].start()

checks = {}
check_results = {}
timers = {}

# Make a public URL to tunnel to this webhook listener
ngrok.connect(5000)
tunnels = ngrok.get_tunnels()
public_url = tunnels[0].public_url
print(f"Webhook listener public url is {public_url}")

# check PD on a schedule
scheduler = BackgroundScheduler()
scheduler.add_job(check_pd, CronTrigger.from_crontab(CHECK_SCHEDULE))
scheduler.start()

