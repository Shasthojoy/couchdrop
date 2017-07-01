import os

from couchdropweb import application

if __name__ == "__main__":
    os.environ["COUCHDROP_API_URL"] = "http://localhost:5088"
    os.environ["COUCHDROP_WEB__API_URL"] = "http://localhost:5088"
    os.environ["COUCHDROP_WEB__REDIRECT_URI"] = "http://localhost:5089"

    os.environ["COUCHDROP_WEB__DROPBOX_KEY"] = "--"
    os.environ["COUCHDROP_WEB__DROPBOX_SECRET"] = "--"
    os.environ["COUCHDROP_WEB__FLASK_SESSION_SECRET"] = "averycomplexsecretthatshouldnotbeusedinproduction"

    application.run(host='0.0.0.0', port=5089, debug=True, threaded=True)