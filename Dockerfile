FROM ubuntu:latest
RUN apt-get update -y && apt-get install -y supervisor software-properties-common vim
RUN add-apt-repository ppa:webupd8team/java
RUN apt-get update
RUN echo "oracle-java8-installer shared/accepted-oracle-license-v1-1 select true" | debconf-set-selections
RUN apt-get install -y oracle-java8-installer maven supervisor python-pip python-dev build-essential postgresql-client-common libpq-dev python-dev curl

# Copy Files over
WORKDIR /app
COPY . /app

# Install the SSH endpoint
RUN cd /app/endpoints/ssh && mvn assembly:assembly
COPY env/supervisor-app.conf /etc/supervisor/conf.d/

# Install the UWSGI applications
RUN pip install uwsgi 
RUN pip install -r service/requirements.txt
RUN pip install -r web/requirements.txt

EXPOSE 5022 8080 8081
CMD ["supervisord", "-n"]


