const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const dbConfig = require('./knexfile');
const server = express();
const knex = require('knex');

const db = knex(dbConfig.development);

const bcrypt = require('bcryptjs');

server.use(express.json());
server.use(cors());



//custom middleware
const secret = 'seeeeeecret!';

function generateToken(user){
    const payload = {
        username: user.username
    };
    const options = {
        expiresIn: '1h',
        jwtid: '12345', //JTI = jwt id, calculated based on the time you give the library
    }
    return jwt.sign(payload, secret, options);
};


function protected(req, res, next){
    //use jwt instead of sessions
    //read the token (string) from the Authorization header
    const token = req.headers.authorization;
    // Is the client sending a token?
    if(token){
        //verify the token
        jwt.verify(token, secret, (err, decodedToken) => {
            if(err) {
                //token is invalid
                res.status(401).json({ message: "Invalid token." })
            } else {
                console.log(decodedToken);
                next();
            }
        })
    } else {
        res.status(401).json({ message: "No token provided." })
    }
};

server.post('/api/register', (req, res) => {
    const creds = req.body;

    const hash = bcrypt.hashSync(creds.password, 10);
    creds.password = hash;

    db('users')
        .insert(creds)
        .then(ids => {
            const id = ids[0];
            //find the user using the id
            db('users').where({id}).first()
                .then(user => {
                    const token = generateToken(user);
                    res.status(201).json({ id: user.id, token})
                })
                .catch(err => res.status(500).send(err))
        })
        .catch(err => res.status(500).send(err))
})

server.post('/api/login', (req, res) => {
    const creds = req.body;

    db('users')
        .where({ username: creds.username })
        .first()
        .then(user => {
            if(user && bcrypt.compareSync(creds.password, user.password)){
                //generate a token
                const token = generateToken(user);
                res.status(200).json({ token})
                //attach that token to the response
                res.status(200).send(`Welcome ${user.username}`)
            } else {
                res.status(401).json({ message: 'You shall not pass!' })
            }
        })
        .catch(err => res.status(500).send(err))
});


server.get('/api/users', protected, (req, res) => {
      db('users')
        .then(users => {
        res.json(users)
        })
        .catch(err => res.send(err));
});

server.get('/', (req, res) => {
    res.send('It is aliiiiiive!')
});




//SERVER

server.listen(3600, () => console.log('\nrunning on port 3600\n'));
