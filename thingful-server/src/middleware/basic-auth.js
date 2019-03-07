'use strict';
const bcrypt = require('bcryptjs');
const AuthService = require('../auth/authService');

function requireAuth(req, res, next){
  const authToken = req.get('Authorization') || '';

  let bearerToken;

  if(!authToken.toLowerCase().startsWith('bearer ')){
    return res.status(401).json({error: 'Missing bearer token'});
  } else {
    bearerToken = authToken.slice(7, authToken.length);
  }
  const [tokenUsername, tokenPassword] = AuthService.parseBasicToken(bearerToken);
 
  if(!tokenUsername || !tokenPassword){
    return res.status(401).json({error: 'Unauthorized request'});
  }

  AuthService.getUserWithUsername(req.app.get('db'), tokenUsername)
    .then(user => {
      if(!user) {
        return res.status(401).json({error: 'Unauthorized request'});
      }
        
      return AuthService.comparePasswords(tokenPassword, user.password)
        .then(passwordsMatch => {
          if(!passwordsMatch) {
            return res.status(401).json({error: 'Unauthorized request'});
          }

          req.user = user;
          next();
        });
    })
    .catch(next);
}

module.exports = {
  requireAuth,
};