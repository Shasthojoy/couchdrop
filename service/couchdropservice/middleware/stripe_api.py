import os

import stripe

COUCHDROP_STANDARD__PLAN_ID="1"
COUCHDROP_PREMIUM__PLAN_ID="2"

def stripe__get_customer(customer_id):
    stripe.api_key = os.environ["COUCHDROP_SERVICE__STRIPE_SECRET_KEY"]
    return stripe.Customer.retrieve(customer_id)


def stripe__create_customer(email_address):
    stripe.api_key = os.environ["COUCHDROP_SERVICE__STRIPE_SECRET_KEY"]
    customer_object = stripe.Customer.create(
        email=email_address,
        description="Customer for %s" % email_address,
    )
    return customer_object


def stripe__cancel_existing_subscriptions(customer_id):
    stripe.api_key = os.environ["COUCHDROP_SERVICE__STRIPE_SECRET_KEY"]
    customer = stripe__get_customer(customer_id)

    for subscription in customer.get("subscriptions", []):
        sub = stripe.Subscription.retrieve(subscription["id"])
        sub.delete()


def stripe__subscribe_customer(customer_id, card_token, plan):
    stripe.api_key = os.environ["COUCHDROP_SERVICE__STRIPE_SECRET_KEY"]
    stripe__cancel_existing_subscriptions(customer_id)

    resolved_plan_id = ""
    if plan == "couchdrop_standard":
        resolved_plan_id = COUCHDROP_STANDARD__PLAN_ID
    if plan == "couchdrop_premium":
        resolved_plan_id = COUCHDROP_PREMIUM__PLAN_ID

    stripe.Subscription.create(
        customer=customer_id,
        items=[
            {
                "plan": resolved_plan_id,
            },
        ],
        source=card_token
    )

