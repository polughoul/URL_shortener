CREATE TABLE users (
    id integer primary key autoincrement,
    name TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);
CREATE TABLE link (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    contact_id INTEGER,
    group_id INTEGER,
    long TEXT NOT NULL,
    short TEXT,
    timestamp TEXT,
    count_click INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE ON UPDATE NO ACTION
);