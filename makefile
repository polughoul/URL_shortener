init:
	cd links && type .\init.sql | .\sqlite3.exe links.sqlite

run:
	cd links && python app.py 