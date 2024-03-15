const sqlite3 = require('sqlite3').verbose();

// Open a database connection
let db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Connected to the users database.');
});

db.serialize(() => {
  // Create a new table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )`);
});

db.close((err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Closed the database connection.');
});