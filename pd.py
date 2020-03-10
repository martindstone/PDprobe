import re
import json
import requests

# Uncomment the section below for low-level HTTPS debugging
# import logging
# import http.client as http_client
# http_client.HTTPConnection.debuglevel = 1
# logging.basicConfig()
# logging.getLogger().setLevel(logging.DEBUG)
# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.DEBUG)
# requests_log.propagate = True

BASE_URL = 'https://api.pagerduty.com'

def auth_header_for_token(token):
    if re.search("^[0-9a-f]{64}$", token):
        return f"Bearer {token}"
    else:
        return f"Token token={token}"

def send_v2_event(payload):
    url = "https://events.pagerduty.com/v2/enqueue"
    headers = {
        "Content-Type": "application/json"
    }
    req = requests.Request(
        method='POST',
        url=url,
        headers=headers,
        json=payload
    )

    prepped = req.prepare()
    response = requests.Session().send(prepped)

    try:
        return response.json()
    except:
        return None

def request(token=None, endpoint=None, method="GET", params=None, data=None, addheaders=None):

    if not endpoint or not token:
        return None


    url = '/'.join([BASE_URL, endpoint])
    headers = {
        "Accept": "application/vnd.pagerduty+json;version=2",
        "Authorization": auth_header_for_token(token)
    }

    if data != None:
        headers["Content-Type"] = "application/json"

    if addheaders:
        headers.update(addheaders)

    req = requests.Request(
        method=method,
        url=url,
        headers=headers,
        params=params,
        json=data
    )

    prepped = req.prepare()
    response = requests.Session().send(prepped)

    try:
        return response.json()
    except:
        return None

def fetch(token=None, endpoint=None, params=None):
    my_params = {}
    if params:
        my_params = params.copy()

    fetched_data = []
    offset = 0
    array_name = endpoint.split('/')[-1]
    while True:
        try:
            r = request(token=token, endpoint=endpoint, params=my_params)
            fetched_data.extend(r[array_name])
        except:
            print(f"Oops! {r}")

        if not (("more" in r) and r["more"]):
            break
        offset += r["limit"]
        my_params["offset"] = offset
    return fetched_data

def fetch_incidents(token=None, params={"statuses[]": ["triggered", "acknowledged"]}):
    return fetch(token=token, endpoint="incidents", params=params)

def fetch_users(token=None, params=None):
    return fetch(token=token, endpoint="users", params=params)

def fetch_escalation_policies(token=None, params=None):
    return fetch(token=token, endpoint="escalation_policies", params=params)

def fetch_services(token=None, params=None):
    return fetch(token=token, endpoint="services", params=params)

def fetch_schedules(token=None, params=None):
    return fetch(token=token, endpoint="schedules", params=params)

def fetch_teams(token=None, params=None):
    return fetch(token=token, endpoint="teams", params=params)
