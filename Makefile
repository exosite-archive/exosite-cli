
VSN = $(shell git describe)

all: exoapi.tgz

.PHONY: VERSION
VERSION:
	echo $(VSN) > VERSION
	sed "s/^VERSION =.*/VERSION = '$(VSN)'/g" -i exosite.py

.PHONY: exoapi.tgz
exoapi.tgz: VERSION
	-rm dist/*
	python setup.py sdist
	rm -rf exosite.egg-info
	cp dist/* exoapi.tgz
	cp dist/* exosite.tgz

.PHONY: upload
upload: exoapi.tgz
	aws s3 cp exosite.tgz exoapi.tgz s3://exosite-tool/
	echo Install Using: sudo pip install https://s3.amazonaws.com/exosite-tool/exosite.tgz
