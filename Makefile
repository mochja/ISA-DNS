all:
	curl -sO https://bootstrap.pypa.io/get-pip.py
	python3 get-pip.py --user --no-wheel --no-setuptools
	python3 -m pip install dnspython