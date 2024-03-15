const sqlite3 = require('sqlite3').verbose();
const argon2 = require('argon2');

function loginUser(username, password) {
  const db = new sqlite3.Database('./users.db');

  db.get(`SELECT password FROM users WHERE username = ?`, [username], async (err, row) => {
    if (err) {
      console.error('Error on login:', err.message);
      return;
    }
    if (row) {
      const match = await argon2.verify(row.password, password);
      if (match) {
        console.log('Login successful!');
      } else {
        console.log('Incorrect password.');
      }
    } else {
      console.log('User not found.');
    }
    db.close();
  });
}

// Usage: node login.js <username> <password>
if (process.argv.length !== 4) {
  console.log('Usage: node login.js <username> <password>');
  process.exit(1);
}

const [,, username, password] = process.argv;
loginUser(username, password);
