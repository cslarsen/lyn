check:
	pyflakes lyn.py
	PYTHONPATH=. /usr/bin/env python tests/lyn_tests.py
