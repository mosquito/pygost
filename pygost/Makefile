PYTHON ?= python

test:
	PYTHONPATH=$(PYTHONPATH):.. $(PYTHON) -m unittest test_gost28147
	PYTHONPATH=$(PYTHONPATH):.. $(PYTHON) -m unittest test_gost28147_mac
	PYTHONPATH=$(PYTHONPATH):.. $(PYTHON) -m unittest test_gost341194
	PYTHONPATH=$(PYTHONPATH):.. $(PYTHON) -m unittest test_gost34112012
	PYTHONPATH=$(PYTHONPATH):.. $(PYTHON) -m unittest test_gost3410
	PYTHONPATH=$(PYTHONPATH):.. $(PYTHON) -m unittest test_gost3410_vko
	PYTHONPATH=$(PYTHONPATH):.. $(PYTHON) -m unittest test_wrap
	PYTHONPATH=$(PYTHONPATH):.. $(PYTHON) -m unittest test_gost3412
	PYTHONPATH=$(PYTHONPATH):.. $(PYTHON) -m unittest test_gost3413
	PYTHONPATH=$(PYTHONPATH):.. $(PYTHON) -m unittest test_x509
	PYTHONPATH=$(PYTHONPATH):.. $(PYTHON) -m unittest test_cms
	PYTHONPATH=$(PYTHONPATH):.. $(PYTHON) -m unittest test_pfx
