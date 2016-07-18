# couchdrop
Cloud SCP Server

Couchdrop is currently split into 3 services. This makes it easily scalable and extensible. It is written in Python using the flask framework and java for the ssh endpoint using the apache sshd library. 

For development purposes getting up and running involves starting each service with applicable properties and running the database migration scripts for the service/api. For the python web apps, there is a main python script called application.py. This sets some environment variables and then launches the flash application. Don't run the system in production like this, I recommend using uwsgi behind a http load balancer. 

# service - The api endpoint
This handles everything and does all the database work as well as the integration with dropbox and amazon s3. Queries are restful and the responses are always in json with corresponding error and response codes.

# web - The web interface
This is the web management interface for couchdrop. Everything here is driven by the api.

# endpoints/ssh - The scp server
This is the ssh/scp server. It listens for ssh connections, authenticates the user against the api and then if everything checks out it will allow the user to upload a file. The file is stored in temporary memory then uploaded to the api which handles the dropbox or s3 integration. Once complete it deletes the files and closes the connection.


