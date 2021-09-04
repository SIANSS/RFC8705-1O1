const https = require('https');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const express = require("express");
const { 'x5t#S256': thumbprint } = require('./helpers/calculate_thumbprint');

const hostname = 'localhost';
const port = 3000;

const options = {
    ca: fs.readFileSync('ca.crt'),
    cert: fs.readFileSync('server.crt'),
    key: fs.readFileSync('server.key'),
    rejectUnauthorized: true,
    requestCert: true,
};


var iss = "Dimosian Atony";
var sub = "dimosian@nzia.io";
var aud = "kyc";
var exp = "4h";


const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
const base64url = require('./helpers/base64url');

const server = https.createServer(options, app);


app.use('/token', (req, res) => {
  console.log(req.body);
  const clientId = req.body.client_id;
  if(!clientId){
    res.statusCode = 401;
    res.end('Invalid Client ID');  
  }
  const cert = req.socket.getPeerCertificate(true);
  var signOptions = {
    issuer : iss,
    subject: sub,
    audience: clientId,
    expiresIn: exp,
    cnf: {
      "x5t#S256": thumbprint(cert.fingerprint256)
    }
  };
  const token = jwt.sign(signOptions, fs.readFileSync('server.key'), { algorithm: 'RS256' });
  res.statusCode = 200;
  res.end(token);
});

app.use('/verify', (req, res) => {
  const authorizationHeader = req.get("Authorization");

  if (!authorizationHeader) {
    return res.status(401).json("missing token");
  }
  const token = authorizationHeader.substring(7);
  // console.log(token);
  var cert = fs.readFileSync('server.crt');
  jwt.verify(token, cert, { algorithms: ['RS256'] }, function(err, decoded) {
    // console.log(err || decoded);
    if(err){
      res.statusCode = 401;
      res.end('Invalid Token');
    } else {
      if(thumbprint(req.socket.getPeerCertificate(true).fingerprint256) !== decoded.cnf["x5t#S256"]){
        res.statusCode = 401;
        res.end('Token Certificate Mismatch');
      }
    }
  });
  res.statusCode = 200;
  res.end('Token Valid');
});


server.listen(port, hostname, () => {
  console.log(`Server running at http://${hostname}:${port}/`);
});
