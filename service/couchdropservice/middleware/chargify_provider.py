import json
import os

import requests

from couchdropservice import config__get


def __chargify__get_customers(email_address):
    key = config__get("COUCHDROP_SERVICE__CHARGIFY_KEY")
    req = requests.get("https://couchdrop.chargify.com/customers.json?q=%s" % email_address, auth=(key, ''))
    all_customers = json.loads(req.text)
    return all_customers


def __charify__get_subscription(customer_id):
    key = config__get("COUCHDROP_SERVICE__CHARGIFY_KEY")
    req = requests.get("https://couchdrop.chargify.com/customers/%s/subscriptions.json" % customer_id, auth=(key, ''))
    for sub in json.loads(req.text):
        subscription_object = sub["subscription"]
        if subscription_object["state"] == "active" or subscription_object["state"] == "trialing":
            return subscription_object["product"]["handle"]
    return None

def __chargify__get_link(customer_id):
    key = config__get("COUCHDROP_SERVICE__CHARGIFY_KEY")
    req = requests.get("https://couchdrop.chargify.com/portal/customers/%s/management_link.json" % customer_id, auth=(key, ''))
    if req.status_code == 200:
        return json.loads(req.text)["url"]
    return None


def chargify__get_subscription_info(email_address):
    customers = __chargify__get_customers(email_address)
    for customer in customers:
        subscription = __charify__get_subscription(customer["customer"]["id"])
        if subscription:
            link = __chargify__get_link(customer["customer"]["id"])
            return subscription, link
    return None, None


