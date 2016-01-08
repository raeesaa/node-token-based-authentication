/**
** Followed tutorial: https://scotch.io/tutorials/authenticate-a-node-js-api-with-json-web-tokens
**
**/

var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var morgan = require('morgan');
var mongoose = require('mongoose');

var jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens
var config = require('./config'); // get our config file
var User = require('./models/User'); // get our mongoose model

var port = process.env.PORT || 3000; // used to create, sign, and verify tokens
mongoose.connect(config.database); // connect to database
app.set('superSecret', config.secret); // secret variable
app.use(bodyParser.urlencoded({
	extended: false
}));
app.use(bodyParser.json());
app.use(morgan('dev'));


//isAuthenticated middleware
var isAuthenticated = function(req, res, next) {

	//Check if token is passed as query parameter, body parameter or in request header

	var token = req.body.token || req.query.token || req.headers['x-access-token'];

	if (token) {

		jwt.verify(token, app.get('superSecret'), {
			algorithms: ['HS384']
		}, function(err, decoded) {

			if (err) {
				return res.json(403, {
					success: false,
					message: "Failed to authenticate token"
				});
			} else {
				console.log(decoded);
				req.decoded = decoded;
				next();
			}

		})

	} else {

		return res.json(403, {
			success: false,
			message: "No token provided"
		});
	}

}

app.get('/', function(req, res) {
	res.send("Welcome to token based authentication sample");
});

app.get('/setup', function(req, res) {

	// create a sample user
	var raeesaa = new User({
		name: 'Raeesaa Metkari',
		password: 'password',
		admin: true
	});

	// save the sample user
	raeesaa.save(function(err) {
		if (err) throw err;

		console.log('User saved successfully');
		res.json({
			success: true
		});
	});
});

var apiRoutes = express.Router();

apiRoutes.get('/', isAuthenticated, function(req, res) {
	res.json({
		message: "Welcome to token based authentication example"
	});
})


apiRoutes.get('/users', isAuthenticated, function(req, res) {
	User.find({}, function(err, users) {
		return res.json(users);
	});
});

apiRoutes.post('/authenticate', function(req, res, next) {
	User.findOne({
		name: req.body.name
	}, function(err, user) {
		if (err) {
			next(err)
		} else {
			if (user) {

				if (user.password == req.body.password) {

					//If user is found and password is correct,
					//we will create a token

					var token = jwt.sign(user, app.get('superSecret'), {
						expiresIn: 60,
						algorithm: 'HS384'
					});

					return res.json({
						success: true,
						token: token,
						message: "Login successful"
					});

				} else {
					res.json(401, {
						success: false,
						message: "Authentication failed. Incorrect password"
					});
				}

			} else {
				res.json(401, {
					success: false,
					message: "Authentication failed. User not found"
				});
			}
		}
	})
})

app.use('/api', apiRoutes);


app.listen(port, function() {
	console.log('Express server is listening on port: ' + port);
});