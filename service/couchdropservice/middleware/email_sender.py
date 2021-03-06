import json

import requests

from couchdropservice import config__get


def mandrill__send_file__email(rec, rec_name, sender_name, filename, file_object_base64_encoded):
    request = {
        "key": config__get("COUCHDROP_SERVICE__MANDRILL_API_KEY"),
        "template_name": "Received a file",
        "template_content": [
            {
                "content": "example content",
                "name": "example name"
            }
        ],
        "message": {
            "subject": "You received a file",
            "from_email": "noreply@couchdrop.io",
            "from_name": "Couchdrop",
            "to": [
                {
                    "email": rec,
                    "name": rec_name,
                    "type": "to"
                }
            ],
            "headers": {
                "Reply-To": "noreply@couchdrop.io"
            },
            "important": False,
            "track_opens": None,
            "track_clicks": None,
            "auto_text": None,
            "auto_html": None,
            "inline_css": None,
            "url_strip_qs": None,
            "preserve_recipients": None,
            "view_content_link": None,
            "tracking_domain": None,
            "signing_domain": None,
            "return_path_domain": None,
            "merge": True,
            "merge_language": "mailchimp",
            "global_merge_vars": [
                {
                    "name": "filename",
                    "content": filename
                },
                {
                    "name": "sender",
                    "content": sender_name
                }
            ],
            "attachments": [
                {
                    "type": "text/plain",
                    "name": filename,
                    "content": file_object_base64_encoded
                }
            ],
        },
        "async": False,
    }

    requests.post("https://mandrillapp.com/api/1.0/messages/send-template.json", data=json.dumps(request))


def mandrill__email_confirm__email(rec, rec_name, confirm_code):
    request = {
        "key": config__get("COUCHDROP_SERVICE__MANDRILL_API_KEY"),
        "template_name": "Confirm email",
        "template_content": [
            {
                "content": "example content",
                "name": "example name"
            }
        ],
        "message": {
            "subject": "Couchdrop Email Confirmation",
            "from_email": "noreply@couchdrop.io",
            "from_name": "Couchdrop",
            "to": [
                {
                    "email": rec,
                    "name": rec_name,
                    "type": "to"
                }
            ],
            "headers": {
                "Reply-To": "noreply@couchdrop.io"
            },
            "important": False,
            "track_opens": None,
            "track_clicks": None,
            "auto_text": None,
            "auto_html": None,
            "inline_css": None,
            "url_strip_qs": None,
            "preserve_recipients": None,
            "view_content_link": None,
            "tracking_domain": None,
            "signing_domain": None,
            "return_path_domain": None,
            "merge": True,
            "merge_language": "mailchimp",
            "global_merge_vars": [
                {
                    "name": "link",
                    "content": "https://my.couchdrop.io/register/awaitingconfirm/%s" % confirm_code
                },
            ]
        },
        "async": False,
    }

    requests.post("https://mandrillapp.com/api/1.0/messages/send-template.json", data=json.dumps(request))


def mandrill__email_password_reset(rec, rec_name, confirm_code):
    request = {
        "key": config__get("COUCHDROP_SERVICE__MANDRILL_API_KEY"),
        "template_name": "Reset Password",
        "template_content": [
            {
                "content": "example content",
                "name": "example name"
            }
        ],
        "message": {
            "subject": "Couchdrop Reset Password",
            "from_email": "noreply@couchdrop.io",
            "from_name": "Couchdrop",
            "to": [
                {
                    "email": rec,
                    "name": rec_name,
                    "type": "to"
                }
            ],
            "headers": {
                "Reply-To": "noreply@couchdrop.io"
            },
            "important": False,
            "track_opens": None,
            "track_clicks": None,
            "auto_text": None,
            "auto_html": None,
            "inline_css": None,
            "url_strip_qs": None,
            "preserve_recipients": None,
            "view_content_link": None,
            "tracking_domain": None,
            "signing_domain": None,
            "return_path_domain": None,
            "merge": True,
            "merge_language": "mailchimp",
            "global_merge_vars": [
                {
                    "name": "link",
                    "content": "https://my.couchdrop.io/resetpassword/%s" % confirm_code
                },
            ]
        },
        "async": False,
    }

    requests.post("https://mandrillapp.com/api/1.0/messages/send-template.json", data=json.dumps(request))
