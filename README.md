#Exam questions period 4

###1: Explain basic security terms like authentication, authorization, confidentiality, integrity, SSL/TLS and provide examples of how you have used them.?

#####Authentication:
Confirming the identity of a client (via some kind of login procedure).

#####Authorization:
Determing whether an authenticated client is allowed to receive a service or perform an operation (via some kind of role definition).

#####Confidentiality (privacy):
Protection from disclosure to unauthorised persons. In other words confidentiality are designed to prevent sensitive information
from reaching the wrong people, while making sure that the right people can in fact get it.

#####Integrity:
Integrity involves maintaining the consistency, accuracy, and trustworthiness of data over its entire life cycle. Data must not be changed in transit, and steps must be taken to ensure that data cannot be altered by unauthorized people (for example, in a breach of confidentiality). These measures include file permissions and user access controls. Version control maybe used to prevent erroneous changes or accidental deletion by authorized users.

#####SSL/TLS:
SSL (Secure Sockets Layer) is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and integral. To be able to create an SSL connection a web server requires an SSL Certificate. When you choose to activate SSL on your web server your web server then creates two cryptographic keys - a Private Key and a Public Key.

The Public Key does not need to be secret and is placed into a Certificate Signing Request (CSR) - a data file also containing your details. During the SSL Certificate application process, the Certification Authority will validate your details and issue an SSL Certificate containing your details and allowing you to use SSL. Your web server will match your issued SSL Certificate to your Private Key. Your web server will then be able to establish an encrypted link between the website and your customer's web browser.

The complexities of the SSL protocol remain invisible to your customers. Instead their browsers provide them with a key indicator to let them know they are currently protected by an SSL encrypted session - the lock icon in the lower right-hand corner, clicking on the lock icon displays your SSL Certificate and the details about it. All SSL Certificates are issued to either companies or legally accountable individuals.

Typically an SSL Certificate will contain your domain name, your company name, your address, your city, your state and your country. It will also contain the expiration date of the Certificate and details of the Certification Authority responsible for the issuance of the Certificate. When a browser connects to a secure site it will retrieve the site's SSL Certificate and check that it has not expired, it has been issued by a Certification Authority the browser trusts, and that it is being used by the website for which it has been issued. If it fails on any one of these checks the browser will display a warning to the end user letting them know that the site is not secured by SSL.

See the Seed folder for code examples for how I have used the different security terms.

###2: Explain basic security threads like: Cross Site Scripting (XSS), SQL Injection and whether something similar to SQL injection is possible with NoSQL databases like MongoDB, and DOS-attacks. Explain/demonstrate ways to cope with these problems?

#####Cross Site Scripting (XSS):
Cross-site Scripting (XSS) refers to client-side code injection attack wherein an attacker can execute malicious scripts (also commonly referred to as a malicious payload) into a legitimate website or web application. XSS is amongst the most rampant of web application vulnerabilities and occurs when a web application makes use of unvalidated or unencoded user input within the output it generates. In order for an XSS attack to take place the vulnerable website needs to directly include user input in its pages. An attacker can then insert a string that will be used within the web page and treated as code by the victim’s browser. That means that it is possible to fx. steal the users sessionCookie.

One way to avoid XSS could be to sanitize user input, and filtering out common HTML special characters such as " < > & ; ".


#####SQL Injection:
SQL injection is a technique to maliciously exploit applications that use client-supplied data in SQL statements. Attackers trick the SQL engine into executing unintended commands by supplying specially crafted string input, thereby gaining unauthorized access to a database in order to view or manipulate restricted data.

SQL injection techniques may differ, but they all exploit a single vulnerability in the application:

Incorrectly validated or nonvalidated string literals are concatenated into a dynamic SQL statement, and interpreted as code by the SQL engine.

In Java we used PreparedStatements, because they make SQL injection impossible.

	public insertUser(String name, String email) {
	   Connection conn = null;
	   PreparedStatement stmt = null;
	   try {
	      conn = setupTheDatabaseConnectionSomehow();
	      stmt = conn.prepareStatement("INSERT INTO person (name, email) values (?, ?)");
	      stmt.setString(1, name);
	      stmt.setString(2, email);
	      stmt.executeUpdate();
	   }
	   finally {
	      try {
	         if (stmt != null) { stmt.close(); }
	      }
	      catch (Exception e) {
	         // log this error
	      }
	      try {
	         if (conn != null) { conn.close(); }
	      }
	      catch (Exception e) {
	         // log this error
	      }
	   }
	}
No matter what characters are in name and email, those characters will be placed directly in the database. They won't affect the INSERT statement in any way.

There are different set methods for different data types -- which one you use depends on what your database fields are. For example, if you have an INTEGER column in the database, you should use a setInt method.

#####Inject NoSQL databases:
NoSQL databases provide looser consistency restrictions than traditional SQL databases. By requiring fewer relational constraints and consistency checks, NoSQL databases often offer performance and scaling benefits. Yet these databases are still potentially vulnerable to injection attacks, even if they aren't using the traditional SQL syntax. Because these NoSQL injection attacks may execute within a procedural[1] language , rather than in the declarative[2] SQL language, the potential impacts are greater than traditional SQL injection.

NoSQL database calls are written in the application's programming language, a custom API call, or formatted according to a common convention (such as XML, JSON, LINQ, etc). Malicious input targeting those specifications may not trigger the primarily application sanitization checks. For example, filtering out common HTML special characters such as < > & ; will not prevent attacks against a JSON API, where special characters include / { } : .

There are now over 150 NoSQL databases available[3] for use within an application, providing APIs in a variety of languages and relationship models.Each offers different features and restrictions. Because there is not a common language between them, example injection code will not apply across all NoSQL databases.

NoSQL injection attacks may execute in different areas of an application than traditional SQL injection. Where SQL injection would execute within the database engine, NoSQL variants may execute during within the application layer or the database layer, depending on the NoSQL API used and data model. Typically NoSQL injection attacks will execute where the attack string is parsed, evaluated, or concatenated into a NoSQL API call.

###3: Explain, at a fundamental level, the technologies involved, and the steps required initialize a SSL connection between a browser and a server and how to use SSL in a secure way?

![alt tag](http://ptgmedia.pearsoncmg.com/images/chap3_0131014684/elementLinks/03fig15.gif)

1) Once the client has established a TCP session on port 443 with the server, the client sends a client hello message. This client hello includes information such as the cipher suites that it supports.

2) The server selects the cipher suite from the list presented and responds with a server hello indicating to the client the ciphers it deems suitable. The client and the server have now agreed on a cipher suite to use.

3) The server then issues the client a copy of its certificate (remember that this certificate also contains the public key). Optionally, the server may request a copy of the client's certificate if client-side authentication is required.

4) Next, the server sends a server hello done message to tell the client it has completed the first phase of the session setup. As there is no key yet, this process is carried out in clear text.

5) The client now generates a random number, encrypts it with its public key, and sends the server the client key. This process is known as the client key exchange. This is the symmetric key that will be used for the duration of the symmetric encryption session. Communication from here on is encrypted.

6) The client now sends a change cipher spec message to the server to say it will now begin using the negotiated cipher suite (determined in step 2) for the duration of the session.

7) Once this is done, the client sends a finished message to the server to say that it is ready.

8) The server, in turn, sends a change cipher spec message to the client using the agreed information. The server also sends out a finished message on completion.

9) A secure encrypted tunnel is now set up, and communication can begin using the symmetric encryption details negotiated.

Source: http://www.informit.com/articles/article.aspx?p=169578&seqNum=4

###4: Explain and demonstrate ways to protect user passwords on our backends, and why this is necessary?

Don't store your passwords in the clear! Because if you do an attacker just needs to find one SQL Injection vulnerability and he's got the password for every one of your users.

#####One-way cryptographic hash:
The idea behind using a one-way algorithm is that the hash value can't be reversed to "decrypt" the password. So how does authentication work? When a user attempts to login, you apply the same one-way algorithm to convert the user-provided password into the hash value, and then compare the two hashes. If they match, then the user-provided password was correct. At no time is the password ever stored in the clear.

Often, developers will hear the advice "use a hash" and interpret that as "run the plaintext password through MD5 or SHA-1 and store the result." But that only solves part of the problem -- the part about using an irreversible algorithm. It doesn't protect against pre-computation. Let's say you've used SHA-1 to hash your passwords, and your USERS table looks like this in the database:

	USER          PASSWORD_HASH
	admin         5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
	bob           fbb73ec5afd91d5b503ca11756e33d21a9045d9d
	jim           7c6a61c68ef8b9b6b061b28c348bc1ed7921cb53

So if you wanted to obtain the original passwords you'd have to run a dictionary or brute force attack, hashing all possible password options with SHA-1 and comparing the output to the stored hashes. This would take a long time but eventually you'd figure some of them out. But what if you already had a list of all 8-character permutations and their corresponding SHA-1 hashes? Now all you have to do is look up the hashes, rather than computing them on-the-fly. This is the idea behind rainbow tables.

An attacker with a SHA-1 rainbow table covering 8-character alphanumeric combinations would quickly look up those three hashes and obtain the original passwords of "password", "p4ssword", and "passw0rd" respectively.

#####Use a salt:
The best defense against pre-computation of raw hashes is salting. To salt a password, you append or prepend a random string of bits to the plaintext password and hash the result. You then store the salt value alongside the hash so that it can be used by the authentication routine.

When the user attempts to login, the system passes the user-provided password along with the stored salt into the hash routine (in this case, md5crypt), and compares the result to the stored hash.

Each bit of salt used doubles the amount of storage and computation required for a pre-computed table. For instance, if we used one bit of salt -- either 0 or 1 -- the rainbow table would have to account for two variations of every password. Eight bits of salt require 2^8, or 256 variations of every password. Use a sufficiently large salt and pre-computation becomes infeasible. For example, the md5crypt utility uses 48 bits of salt (and for an extra layer of protection, it runs 1000 iterations of MD5 to slow down dictionary attacks).

There are a couple of common mistakes that people make with regard to salting. First, don't use the same salt every time. If you do, you're not really increasing the search space because the attacker only has to account for a single salt value. Second, don't worry about protecting the salt values, they're not secrets. The added security is derived not from the secrecy of the salt but rather by the amount it increases the resources required for pre-computation.

###5: Explain about password hashing, salts and the difference between bcrypt and older (not recommended) algorithms like sha1, md5 etc?
bcrypt is an algorithm that uses Blowfish internally. It is not an encryption algorithm itself. It is used to irreversibly obscure passwords, just as hash functions are used to do a "one-way hash".

Cryptographic hash algorithms are designed to be impossible to reverse. In other words, given only the output of a hash function, it should take "forever" to find a message that will produce the same hash output. In fact, it should be computationally infeasible to find any two messages that produce the same hash value. Unlike a cipher, hash functions aren't parameterized with a key; the same input will always produce the same output.

If someone provides a password that hashes to the value stored in the password table, they are authenticated. In particular, because of the irreversibility of the hash function, it's assumed that the user isn't an attacker that got hold of the hash and reversed it to find a working password.

Now consider bcrypt. It uses Blowfish to encrypt a magic string, using a key "derived" from the password. Later, when a user enters a password, the key is derived again, and if the ciphertext produced by encrypting with that key matches the stored ciphertext, the user is authenticated. The ciphertext is stored in the "password" table, but the derived key is never stored.

In order to break the cryptography here, an attacker would have to recover the key from the ciphertext. This is called a "known-plaintext" attack, since the attack knows the magic string that has been encrypted, but not the key used. Blowfish has been studied extensively, and no attacks are yet known that would allow an attacker to find the key with a single known plaintext.

So, just like irreversible algorithms based cryptographic digests, bcrypt produces an irreversible output, from a password, salt, and cost factor. Its strength lies in Blowfish's resistance to known plaintext attacks, which is analogous to a "first pre-image attack" on a digest algorithm. Since it can be used in place of a hash algorithm to protect passwords, bcrypt is confusingly referred to as a "hash" algorithm itself.

Assuming that rainbow tables have been thwarted by proper use of salt, any truly irreversible function reduces the attacker to trial-and-error. And the rate that the attacker can make trials is determined by the speed of that irreversible "hash" algorithm. If a single iteration of a hash function is used, an attacker can make millions of trials per second using equipment that costs on the order of $1000, testing all passwords up to 8 characters long in a few months.

If however, the digest output is "fed back" thousands of times, it will take hundreds of years to test the same set of passwords on that hardware. Bcrypt achieves the same "key strengthening" effect by iterating inside its key derivation routine, and a proper hash-based method like PBKDF2 does the same thing; in this respect, the two methods are similar.

###Example of how i have used bcrypt to secure the user password:

	UserSchema.pre('save', function (next) {
	    var user = this;
	    if (this.isModified('password') || this.isNew) {
	        bcryptjs.genSalt(10, function (err, salt) {
	            if (err) {
	                return next(err);
	            }
	            bcryptjs.hash(user.password, salt, function (err, hash) {
	                if (err) {
	                    return next(err);
	                }
	                user.password = hash;
	                next();
	            });
	        });
	    } else {
	        return next();
	    }
	});

###6: Explain about JSON Web Tokens (jwt) and why they are very suited for a REST-based API?
JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object.

This information can be verified and trusted because it is digitally signed.

JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA

#####Benefits:
- Compact: Because of its smaller size, JWTs can be sent through an URL, POST parameter, or inside an HTTP header.
- The payload contains all the required information about the user, avoiding the need to query the database more than once

JSON Web Tokens consist of three parts separated by dots:
#####Header:
The header typically consists of two parts: the type of the token (=JWT), and the hashing algorithm being used (HMAC SHA256 or RSA)

	{
	  "typ": "JWT",
	  "alg": "HS256"
	}

#####Payload:
The second part of the token is the payload, which contains the claims. Claims are statements about an entity (typically, the user) and additional metadata. There are three types of claims: reserved, public, and private claims.

	{
	  "sub": "1234567890",
	  "name": "John Doe",
	  "admin": true
	}
#####Signature:
The signature part is created by taking the encoded header, the encoded payload, a secret, the algorithm specified in the header, and sign that.
The signature is used to verify that the sender of the JWT is who it says it is and to ensure that the message wasn't changed along the way.

Using the HMAC SHA256 algorithm, the signature will be created in the following way:

	HMACSHA256(
	  base64UrlEncode(header) + "." +
	  base64UrlEncode(payload),
	  secret)

#####Benefits of using a token-based approach:
JSON Web Tokens are a more modern approach to authentication. As the web moves to a greater separation between the client and server, JWT provides a wonderful alternative to traditional cookie based authentication models.

JWTs provide a way for clients to authenticate every request without having to maintain a session or repeatedly pass login credentials to the server.


- Cross-domain / CORS: cookies + CORS don't play well across different domains. A token-based approach allows you to make AJAX calls to any server, on any domain because you use an HTTP header to transmit the user information

- Stateless: there is no need to keep a session store, the token is a self-contanined entity that conveys all the user information.

- Decoupling: you are not tied to a particular authentication scheme. The token might be generated anywhere, hence your API can be called from anywhere with a single way of authenticating those calls.

- Mobile ready: when you start working on a native platform (iOS, Android, Windows 8, etc.) cookies are not ideal when consuming a secure API (you have to deal with cookie containers). Adopting a token-based approach simplifies this a lot.

- CRSF: since you are not relying on cookies, you don't need to protect against cross site requests.

###7: Explain and demonstrate a system using jwt's, focusing on both client and server side?
See the Seed folder for a complete system example:

In the Example below i show how the client makes a post request for authentication, and stores the token in a sessionStorage.

	$scope.submit = function () {
        $http
            .post('http://localhost:3000/api/authenticate', $scope.user)
            .success(function (data, status, headers, config) {
                $window.sessionStorage.id_token = data.token;
                $scope.isAuthenticated = true;
                $scope.error = false;
            })
            .error(function (data, status, headers, config) {
                // Erase the token if the user fails to log in
                delete $window.sessionStorage.id_token;
                $scope.isAuthenticated = false;

                // Handle login errors here
                $scope.error = true;
                $scope.msg = 'Error: Invalid user or password';
            });
	    };


The code example below demonstrates how the server receives the authenticate request, and response with a JWT.

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

In the subsequent request to the server, the client adds an Authorization header with the token.

	myApp.factory('authInterceptor', function ($rootScope, $q, $window) {

	    return {
	        request: function (config) {
	            config.body = {};
	            config.headers = config.headers || {};
	            if ($window.sessionStorage.id_token) {
	                config.headers.authorization = $window.sessionStorage.id_token;
	            }
	            return config;
	        },
	        responseError: function (rejection) {
	            if (rejection.status === 401) {
	                // handle the case where the user is not authenticated
	            }
	            return $q.reject(rejection);
	        }
	    };
	});

	myApp.config(function ($httpProvider) {
	    $httpProvider.interceptors.push('authInterceptor');
	});


###8: Explain and demonstrate use of the npm passportjs module?
See the Seed folder for a complete system example:

First of all we need to declare that we will use the passport package.

	// Use the passport package in our application
	app.use(passport.initialize());

Then we need a strategy to fx. authenticate the user from a jwt like example below.

	ExtractJwt = require("passport-jwt").ExtractJwt;
	var jwt = require("jwt-simple");
	var User = require("../models/user");
	var jwtConfig = require("../config/jwtConfig").jwtConfig;

	module.exports = function(passport) {

	    var opts = {};
	    opts.secretOrKey = jwtConfig.secret;
	    opts.issuer = jwtConfig.issuer;
	    opts.audience = jwtConfig.audience;
	    opts.jwtFromRequest = ExtractJwt.fromAuthHeader();
	    passport.use(new JwtStrategy(opts, function(jwt_payload,done) {
	        User.findOne({username: jwt_payload.sub}, function(err, user) {
	            if(err) {
	                return done(err,false);
	            }
	            if(user) {
	                done(null, user);
	            }
	            else{
	                done(null,false,"User found in token not fount");
	            }
	        })
	    }))
	};

And then we use the passport to secure our api like this:

	app.use('/api', function (req, res, next) {
	    passport.authenticate('jwt', {session: false}, function (err, user, info) {
	        if (err) {
	            res.status(403).json({mesage: "Token could not be authenticated", fullError: err})
	        }
	        if (user) {
	            return next();
	        }
	        return res.status(403).json({mesage: "Token could not be authenticated", fullError: info});
	    })(req, res, next);
	});

###9: Explain, at a very basic level, OAuth 2 + OpenID Connect and the problems it solves.
OAuth is an authentication protocol that allows users to register with your web application using an external provider, without the need to input their username and password. OAuth is mainly used by social platforms, such as Facebook, Twitter, and Google, to allow users to register with other websites using their social account.

OAuth 2.0, is a framework, specified by the IETF in RFCs 6749 and 6750 (published in 2012) designed to support the development of authentication and authorization protocols. It provides a variety of standardized message flows based on JSON and HTTP; OpenID Connect uses these to provide Identity services.

OpenID lets app and site developers authenticate users without taking on the responsibility of storing and managing passwords in the face of an Internet that is well-populated with people trying to compromise your users’ accounts for their own gain.

###10: Demonstrate, with focus on security, a proposal for an Express/Mongo+Angular-seed with built in support for most of the basic security problems, SSL and ready to deploy on your favourite Cloud Hosting Service.

See the Seed folder for a complete application example:
