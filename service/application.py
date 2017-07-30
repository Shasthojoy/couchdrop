import os

from couchdropservice import application

if __name__ == "__main__":
    os.environ["COUCHDROP_SERVICE__SQLALCHEMY_DATABASE_URI"] = "--"
    os.environ["COUCHDROP_SERVICE__SQLALCHEMY_POOLSIZE_MAX"] = "10"

    os.environ["COUCHDROP_SERVICE__CHARGIFY_KEY"] = "--"
    os.environ["COUCHDROP_SERVICE__MANDRILL_API_KEY"] = "--"

    os.environ["COUCHDROP_SERVICE__AWS_KEY"] = "--"
    os.environ["COUCHDROP_SERVICE__AWS_SECRET"] = "--"
    os.environ["COUCHDROP_SERVICE__AWS_HOSTED_S3_BUCKET"] = "couchdrophosted"

    application.run(host='0.0.0.0', port=5088, debug=True, threaded=True)