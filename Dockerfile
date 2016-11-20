FROM python:3.4

RUN curl -sL https://deb.nodesource.com/setup_6.x | bash -
RUN apt-get install -y nodejs && npm install -g nodemon

WORKDIR /usr/src/myapp
COPY . /usr/src/myapp

EXPOSE 53
EXPOSE 53/udp

CMD ["nodemon", "-e", ".py", "--exec", "python", "./roughtDNS"]
