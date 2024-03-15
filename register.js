const sqlite3 = require('sqlite3').verbose();
const argon2 = require('argon2');

function registerUser(username, password) {
  const db = new sqlite3.Database('./users.db');
  
  argon2.hash(password)
    .then(hash => {
      const sql = `INSERT INTO users (username, password) VALUES (?, ?)`;
      db.run(sql, [username, hash], function(err) {
        if (err) {
          console.error('Error registering new user:', err.message);
          return;
        }
        console.log(`User ${username} registered successfully.`);
      });
    })
    .catch(err => {
      console.error('Argon2 hashing error:', err.message);
    })
    .finally(() => {
      db.close();
    });
}

// Usage: node register.js <username> <password>
if (process.argv.length !== 4) {
  console.log('Usage: node register.js <username> <password>');
  process.exit(1);
}

const [,, username, password] = process.argv;
registerUser(username, password);