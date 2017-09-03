from flask import render_template

from couchdropwebsite import application

@application.route("/status")
def status():
    return "OK"


@application.route("/")
def landing():
    return render_template("landing.html")

@application.route("/privacy")
def privacy():
    return render_template("privacy.html")

