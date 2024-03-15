const express = require('express')
const logger = require('morgan')

const cookieParser = require('cookie-parser')

const app = express()
const port = 3000

const sqlite3 = require('sqlite3').verbose();
const argon2 = require('argon2');

const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt;

const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16)

app.use(cookieParser())
app.use(logger('dev'))

passport.use('username-password', new LocalStrategy(
  {
    usernameField: 'username',
    passwordField: 'password',
    session: false
  },
  function (username, password, done) {
    const db = new sqlite3.Database('./users.db');
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, row) => {
      db.close(); // Ensure the database connection is closed
      if (err) {
        return done(err);
      }
      if (!row) {
        return done(null, false, { message: 'Incorrect username.' });
      }
      try {
        const match = await argon2.verify(row.password, password);
        if (match) {
          // Create a user object based on the row data to return
          const user = {
            id: row.id,
            username: row.username,
            description: 'a user that deserves to get to this server',
          };
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect password.' });
        }
      } catch (error) {
        return done(error);
      }
    });
  }
))

passport.use('jwtCookie', new JwtStrategy(
  {
    jwtFromRequest: ExtractJwt.fromExtractors([(req) => {
      return req?.cookies?.jwt;
    }]),
    secretOrKey: jwtSecret,
  },
  (jwtPayload, done) => {
    const db = new sqlite3.Database('./users.db');
    // Use the jwtPayload.sub, which should contain the username, to look up the user
    db.get("SELECT * FROM users WHERE username = ?", [jwtPayload.sub], (err, row) => {
      db.close(); // Ensure the database connection is closed
      if (err) {
        return done(err);
      }
      if (!row) {
        return done(null, false);
      }

      // Assuming your JWT tokens are generated including user roles or other relevant info
      const user = {
        id: row.id,
        username: row.username,
        description: 'a user that deserves to get to this server',
        role: jwtPayload.role ?? 'user', // Default to 'user' if no role specified in the token
      };
      return done(null, user);
    });
  }
))

app.use(express.urlencoded({ extended: true }))
app.use(passport.initialize())

app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })  // we created this file before, which defines an HTML form for POSTing the user's credentials to POST /login
  }
)


app.post('/login',
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => {
    // This is what ends up in our JWT
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    // From now, just send the JWT directly to the browser. Later, you should send the token inside a cookie.
    res.cookie('jwt', token, {httpOnly: true, secure: true})
    res.redirect('/')
    // And let us log a link to the jwt.io debugger for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)

app.get('/logout',
  (req,res) => {
    res.cookie('jwt', '', { expires: new Date(0), path: '/', httpOnly: true, secure: true });
    res.redirect('/login')
  }
)

app.get('/', 
  passport.authenticate(
    'jwtCookie',
    {session: false, failureRedirect: '/login'}
  ),
  (req,res) => {
    res.send(`Welcome to your private page, ${req.user.username}!`)
  }
)

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
