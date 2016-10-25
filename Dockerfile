FROM python:3.3

RUN curl -sL https://deb.nodesource.com/setup_6.x | bash -
RUN apt-get install -y nodejs && npm install -g nodemon

WORKDIR /usr/src/myapp
COPY . /usr/src/myapp

EXPOSE 53

CMD ["nodemon", "-e", ".py", "--exec", "bash -c", "./roughtDNS"]
