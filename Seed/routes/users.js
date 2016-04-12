/**
 * Created by sebastiannielsen on 07/04/2016.
 */
var express = require('express');
var User = require('../models/user'); // get the mongoose model
var jwt = require('jwt-simple');
var jwtConfig = require("../config/jwtconfig").jwtConfig;

// bundle our routes
var router = express.Router();


// create a new user account (POST http://localhost:8080/api/signup)
router.post('/signup', function (req, res) {
    if (!req.body.username || !req.body.password) {
        res.json({success: false, msg: 'Please pass name and password'});
    } else {
        var newUser = new User({
            username: req.body.username,
            password: req.body.password
        });
        // save user
        newUser.save(function (err) {
            if (err) {
                return res.status(401).json({msg: 'Username already exists.', error: err});
            } else {
                res.status(200).json({msg: 'Successful created new user.'});
            }
        });
    }
});

router.post('/authenticate', function (req, res) {
    User.findOne({
        username: req.body.username
    }, function (err, user) {
        if (err) throw err;

        if (!user) {
            res.status(401).json({msg: 'Authentication failed. User not found.'});
        } else {
            user.comparePassword(req.body.password, function (err, isMatch) {
                if (isMatch && !err) {
                    // if user is found and password is right. Create a token
                    var iat = new Date().getTime() / 1000;  //convert to seconds
                    var exp = iat + jwtConfig.tokenExpirationTime;
                    var payload = {
                        aud: jwtConfig.audience,
                        iss: jwtConfig.issuer,
                        iat: iat,
                        exp: exp,
                        sub: user.username
                    };
                    var token = jwt.encode(payload, jwtConfig.secret);
                    // return the information including token as JSON
                    res.status(200).json({token: 'JWT ' + token});
                } else {
                    res.status(401).json({msg: 'Authentication failed. Wrong password.'});
                }
            });
        }
    });
});


module.exports = router;