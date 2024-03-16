const sqlite3 = require('sqlite3').verbose();
const argon2 = require('argon2');

function registerUser(username, password) {
  const db = new sqlite3.Database('./users.db');
  
  const fastOptions = {
    type: argon2.argon2id,
    timeCost: 2,
    memoryCost: 4096,
    parallelism: 1
  };
  
  // Slow setup: Higher cost parameters
  const slowOptions = {
    type: argon2.argon2id,
    timeCost: 4,
    memoryCost: 65536,
    parallelism: 2
  };
  
  const options = fast ? fastOptions : slowOptions;

  argon2.hash(password, options)
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
if (process.argv.length < 4 || process.argv.lenght > 5) {
  console.log('Usage: node register.js <username> <password> [fast|slow]');
  process.exit(1);
}

const [,, username, password] = process.argv;
const fast = process.argv.length === 4 || process.argv[4] === 'fast';
registerUser(username, password, fast);
