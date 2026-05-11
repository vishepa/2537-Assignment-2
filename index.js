
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

app.set('view engine', 'ejs');


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

function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidationMiddleware(req, res, next) {
  if (isValidSession(req)) {
    next();
  } else {
    res.redirect('/login');
  }
}

function isAdmin(req) {
  if (req.session.user_type === 'admin') {
    return true;
  }
  return false;
}

function adminAuthorizationMiddleware(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("errorMessage", {error: "Not Authorized"});
    return;
  } else {
    next();
  }
}

app.get('/', (req, res) => {

  if (!req.session.authenticated) {

    res.render('home');
  } else {
    res.redirect('/loggedin');
  }
});

app.get('/login', (req,res) => {

  const errorMsg = req.query.error ? `<p style="color:red">${req.query.error}</p>` : '';

    res.render('login', { error: req.query.error});
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

  const results = await userCollection.find({username: username}).project({username: 1, password: 1, user_type: 1, _id: 1}).toArray();

  console.log(results);
  if (results.length != 1) {
    console.log('user not found');
    return res.redirect(`/login?error=${encodeURIComponent('Invalid username or password')}`);
  }

  if (await bcrypt.compare(password, results[0].password)) {
    console.log('password correct');
    req.session.authenticated = true; 
    req.session.username = username;
    req.session.user_type = results[0].user_type;
    req.session.cookie.maxAge = 60 * 60 * 1000;
    res.redirect('loggedin');
  } else {
    console.log('incorrect password');
    return res.redirect(`/login?error=${encodeURIComponent('Invalid username or password')}`);
  }

});

app.use('/loggedin', sessionValidationMiddleware);

app.get('/loggedin', (req,res) => {

  res.render('logged-in-home', { username: req.session.username});

});

app.get('/logout', (req,res) => {
  req.session.destroy();

  res.redirect('/');

});

app.get('/signup', (req,res) => {

    // const errorMsg = req.query.error ? `<p style="color:red">${req.query.error}</p>` : '';

    // let signupForm = `
    // <h3>Sign-Up</h3> <br><br>

    // ${errorMsg}
    // <form action='/recordUser' method='post'>
    // <input name='username' type='text' placeholder='username'> <br><br>
    // <input name='email' type='email' placeholder='email'> <br><br>
    // <input name='password' type='password' placeholder='password'> <br><br>
    // <button type="submit">Submit</button>
    // </form>
    // `;
    res.render('signup', { error: req.query.error});
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

  await userCollection.insertOne({username: username, password: encrptedPassword, email: email, user_type: 'user'});

    req.session.authenticated = true;
    req.session.email = email;
    req.session.username = username;
    req.session.user_type = 'user';
    req.session.cookie.maxAge = 60 * 60 * 1000;
    res.redirect('/loggedin');



  


});

app.get('/members', (req,res) => {

  if (!req.session.authenticated) {
    res.redirect('/');
    return;
  }

  res.render('members', { username: req.session.username});

});

app.get('/admin', sessionValidationMiddleware, adminAuthorizationMiddleware, async (req,res) => {

  const result = await userCollection.find().project({username: 1, user_type: 1, _id: 1}).toArray();

  res.render('admin', { users: result});

});

app.post('/admin/:action', sessionValidationMiddleware, adminAuthorizationMiddleware, async (req,res) => {

  const action = req.params.action;

  const usernameSchema = Joi.string().alphanum().min(3).max(30).required();

  if ( usernameSchema.validate(req.body.username).error ) {
    res.status(400);
    return res.render("errorMessage", {error: "Invalid username"});
  }

  const actionSchema = Joi.string().valid('promote', 'demote').required();
  if ( actionSchema.validate(action).error ) {
    res.status(400);
    return res.render("errorMessage", {error: "Invalid action"});
  }

  const newType = action === 'promote' ? 'admin' : 'user';

  await userCollection.updateOne(
    { username: req.body.username },
    { $set: { user_type: newType } }
  )

  res.redirect('/admin');

});

app.use((req, res) => {
  res.status(404);
  res.render('pnf');
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});