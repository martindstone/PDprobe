# PDprobe
Check the health of various PagerDuty systems

## Installation

From a shell:
```
python3 -m venv venv                 # create a python 3 virtual environment
. venv/bin/activate                  # activate it
pip install -r requirements.txt      # install dependencies
```

## Usage

Get a read/write PagerDuty API token (Configuration > API Access in the PD UI) and then in your shell:
```
TOKEN=<YOUR_API_TOKEN> flask run
```

The script will check PagerDuty every minute (by default) and report the results. It does the following actions with each check:

* Creates a local listener to receive PagerDuty webhooks
* Sets up a tunnel to receive webhooks locally using ngrok
* Creates an escalation policy with a single user in it
* Creates a service with that escalation policy
* Adds a PagerDuty Events v2 integration to the service
* Adds a PagerDuty Generic v2 webhook to the service
* Sends an alert to the new integration
* Waits up to 10 seconds to receive an incident trigger webhook from PagerDuty
* Destroys the escalation policy, service, integration and webhook
* Reports success or failure in three areas: rest, events and webhooks. 

See the `report_results` function in app.py for an example of the report structure.

## Customization:

* Change the `CHECK_SCHEDULE` variable at the top of app.py to check at an appropriate interval  some examples are provided in the file
* Change the `report_results` function at the top of app.py to do something useful with the test results. In the default provided, it just prints the results to the terminal. 