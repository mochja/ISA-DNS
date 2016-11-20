all:
	curl -sO https://bootstrap.pypa.io/get-pip.py
	python3 get-pip.py --user --no-wheel --no-setuptools
	python3 -m pip install --user dnspython

archive:
	tar -cvf xmochn00.tgz Makefile helpers.py roughtDNS readme config.py cli.py
