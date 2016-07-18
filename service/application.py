import os

from couchdropservice import application

if __name__ == "__main__":
    os.environ["SQLALCHEMY_DATABASE_URI"] = "--"
    os.environ["SQLALCHEMY_POOLSIZE_MAX"] = "10"

    application.run(host='0.0.0.0', port=5088, debug=True, threaded=True)