
require('dotenv').config();
const express = require('express');
const session = require('express-session'); 
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const mongoSanitize = require('express-mongo-sanitize');

const app = express();
const port = process.env.PORT || 3000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

const { database } = require('./databaseConnection');
const userCollection = database.db(process.env.MONGODB_USER_DATABASE).collection('users');

app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));


var mongoStore = MongoStore.create({

  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
  crypto: {
    secret: mongodb_session_secret
  }

});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    resave: false,
    saveUninitialized: true
}));

app.get('/', (req, res) => {

  if (!req.session.authenticated) {

    res.send(`
      <form action="/login" method="get" style="display:inline">
        <button type="submit">Login</button>
      </form>
      <form action="/signup" method="get" style="display:inline">
        <button type="submit">Signup</button>
      </form>
    `);
  } else {
    res.redirect('/loggedin');
  }
});

app.get('/login', (req,res) => {

  const errorMsg = req.query.error ? `<p style="color:red">${req.query.error}</p>` : '';

    let loginForm = `
    <h3>Log-In</h3> <br><br>
    ${errorMsg}
    <form action='/loggingin' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button type="submit">Submit</button>
    </form>
    `;
    res.send(loginForm);
});


app.post('/loggingin', async (req,res) => {

  let username = req.body.username;
  let password = req.body.password;

  const schema = Joi.string().alphanum().min(3).max(30).required();
  const result = schema.validate(username);

  if (result.error != null) {
    console.log(result.error);
    return res.redirect(`/login?error=${encodeURIComponent('Invalid username or password')}`);
  }

  const results = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 0}).toArray();

  console.log(results);
  if (results.length != 1) {
    console.log('user not found');
    return res.redirect(`/login?error=${encodeURIComponent('Invalid username or password')}`);
  }

  if (await bcrypt.compare(password, results[0].password)) {
    console.log('password correct');
    req.session.authenticated = true; 
    req.session.username = username;
    req.session.cookie.maxAge = 60 * 60 * 1000;
    res.redirect('loggedin');
  } else {
    console.log('incorrect password');
    return res.redirect(`/login?error=${encodeURIComponent('Invalid username or password')}`);
  }

});

app.get('/loggedin', (req,res) => {

  if (!req.session.authenticated) {
    res.redirect('/login');
    return;
  }

  let loggedInMsg = `

    <h1>Welcome, ${req.session.username}!</h1>
    <form action='/members' method='get'>
    <button type='submit'> Go to members area </button>
    </form>
    <form action='/logout' method='get'>
    <button type='submit'>Logout</button>
    </form>
  `;

  res.send(loggedInMsg);

});

app.get('/logout', (req,res) => {
  req.session.destroy();
  let loggedOutMsg = `
  <p>You are now logged out.</p>
  `;

  res.redirect('/');

});

app.get('/signup', (req,res) => {

    const errorMsg = req.query.error ? `<p style="color:red">${req.query.error}</p>` : '';

    let signupForm = `
    <h3>Sign-Up</h3> <br><br>

    ${errorMsg}
    <form action='/recordUser' method='post'>
    <input name='username' type='text' placeholder='username'> <br><br>
    <input name='email' type='email' placeholder='email'> <br><br>
    <input name='password' type='password' placeholder='password'> <br><br>
    <button type="submit">Submit</button>
    </form>
    `;
    res.send(signupForm);
});

app.post('/recordUser', async (req,res) => {

  let username = req.body.username;
  let password = req.body.password;
  let email = req.body.email;

  const schema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')).required(),
    email: Joi.string().email().required()
  });

  const result = schema.validate({ username, password, email });

  if (result.error) {
    const msg = result.error.details.map(e => e.message).join(', ');
    return res.redirect(`/signup?error=${encodeURIComponent(msg)}`);

  }

  const existingUser = await userCollection.findOne({ username: username });
  if (existingUser) {
    return res.redirect(`/signup?error=${encodeURIComponent('Username already taken')}`);
  }

  let encrptedPassword = await bcrypt.hash(password, 10);

  await userCollection.insertOne({username: username, password: encrptedPassword, email: email});

    req.session.authenticated = true;
    req.session.email = email;
    req.session.username = username;
    req.session.cookie.maxAge = 60 * 60 * 1000;
    res.redirect('/loggedin');



  


});

app.get('/members', (req,res) => {

  if (!req.session.authenticated) {
    res.redirect('/');
    return;
  }

  const images = ['bingzoid.png', 'ben.png', 'glup.png'];
  const randomImage = images[Math.floor(Math.random() * images.length)];

  res.send(`
    <h1>Members Only Area</h1>
    <p>Hello, ${req.session.username}!</p>

    <img src="/${randomImage}" alt="Random Image" style="max-width:300px;"><br><br>
    <form action="/logout" method="get" style="display:inline">
        <button type="submit">Log Out</button>
      </form>
  `);

});

app.use((req, res) => {
  res.status(404);
  res.send('404 - Page Not Found');
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});