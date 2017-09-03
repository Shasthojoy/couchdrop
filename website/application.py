import os

from couchdropwebsite import application

if __name__ == "__main__":
    application.run(host='0.0.0.0', port=5090, debug=True, threaded=True)