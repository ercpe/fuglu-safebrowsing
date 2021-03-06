TARGET?=tests

test_default_python:
	PYTHONPATH="." python -m pytest tests/ --junit-xml testresults.xml -rxsw -v

test_py2:
	@echo Executing test with python2
	PYTHONPATH="." python2 -m pytest tests/ --junit-xml testresults.xml -rxsw -v

test_py3:
	@echo Executing test with python3
	PYTHONPATH="." python3 -m pytest tests/ --junit-xml testresults.xml -rxsw -v

test: test_py2 test_py3

compile:
	@echo Compiling python code
	python -m compileall fuglu_safebrowsing

compile_optimized:
	@echo Compiling python code optimized
	python -O -m compileall fuglu_safebrowsing

coverage:
	coverage erase
	PYTHONPATH="." coverage run --source='fuglu_safebrowsing' --branch -m py.test -qq tests/
	coverage xml -i
	coverage report -m

sonar:
	/usr/local/bin/sonar-scanner/bin/sonar-scanner

clean:
	find -name "*.py?" -delete
	rm -f coverage.xml
	rm -f testresults.xml
	rm -fr htmlcov dist *.egg-info

travis: compile compile_optimized test_default_python coverage
jenkins: travis sonar
