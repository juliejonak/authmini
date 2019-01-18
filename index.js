const express = require('express');
const cors = require('cors');
const session = require('express-session');


const db = require('./database/dbHelpers');

const server = express();
const bcrypt = require('bcryptjs');

server.use(express.json());
server.use(cors());

server.use(session({
  name: 'notsession', // default is connect.sid
  secret: 'nobody tosses a dwarf!', //this allows us to encrypt or unencrypt. we wouldn't want this to be hard coded or a string.
  cookie: {
    maxAge: 1 * 24 * 60 * 60 * 1000, //the age of our cookie
  }, // this is 1 day in milliseconds
  httpOnly: true, // don't let JS code access cookies. Browser extensions run JS code on your browser!
  resave: false, //forces the session to be saved back to the session store, even if the session wasn't modified during the request
  saveUninitialized: false, //do we want to make people give their consent for cookies? thing EU's GDPR laws
}));




//custom middleware
function protect(req, res, next){
  if(req.session && req.session.userId){
    next();
  } else {
    res.status(400).send('access denied')
  }
};


server.get('/', (req, res) => {
  res.send('Its Alive!');
});

// protect this route, only authenticated users should see it
server.get('/api/users', protect, (req, res) => {
  db.findUsers()
    .then(users => {
      res.json(users)
    })
    .catch(err => res.send(err));
});

server.post('/api/register', (req, res) => {
  const user = req.body;
  user.password = bcrypt.hashSync(user.password);
  db.insertUser(user)
    .then(ids => {
      res.status(201).json({id: ids[0]})
    })
    .catch(err => {
      res.status(500).send(err)
    })
})

server.post('/api/login', (req, res) => {
  const creds = req.body;
  db.findByUsername(creds.username)
    .then(users => {
      //if username is valid and hashed passwords math
      if(users.length && bcrypt.compareSync(creds.password, users[0].password)){
        req.session.userId = users[0].id;
        //redirect
        res.json({ info: "correct" })
      } else {
        //redirect to the login screen with a new error message
        res.status(404).json({ error: 'Invalid username or password' })
      }
    })
    .catch(err => {
      res.status(500).send(err)
    })
})


server.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if(err){
      res.status(500).send('failed to logout')
    } else {
      res.send('logout successful')
    }
  })
})

server.listen(3300, () => console.log('\nrunning on port 3300\n'));
