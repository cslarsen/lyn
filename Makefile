PYTHON := python
PYFLAKES := pyflakes

default: test

test:
	$(PYTHON) setup.py test
	PYTHONPATH=. $(PYTHON) examples/return-123.py

check: test

dist:
	rm -rf dist/*
	WHEEL_TOOL=$(shell which wheel) $(PYTHON) setup.py sdist bdist_wheel

publish: dist
	find dist -type f -exec gpg --detach-sign -a {} \;
	twine upload dist/*

setup-pypi-test:
	$(PYTHON) setup.py register -r pypitest
	$(PYTHON) setup.py sdist upload -r pypitest

setup-pypi-publish:
	$(PYTHON) setup.py register -r pypi
	$(PYTHON) setup.py sdist upload --sign -r pypi

lint:
	$(PYFLAKES) lyn/*.py tests/*.py

clean:
	find . -name '*.pyc' -exec rm -f {} \;
	find . -name __pycache__ -type d | xargs rm -rf
	rm -rf lyn.egg-info .eggs build dist .tox
