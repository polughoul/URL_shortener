init:
	cd links && type .\init.sql | .\sqlite3.exe links.sqlite

run:
	cd links && python run.py 

lint:
	cd links && pylint app.py
