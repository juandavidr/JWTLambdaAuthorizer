'use strict';
const jwt = require('jsonwebtoken');

console.log('Loading token');


exports.create_access_token = function(result) {

    //Returns new JWT Token.
    var jwt_info = jwt.sign({
        "sub": "ev-connect",
        "exp": Date.now() + 300
    }, process.env.TOKEN_SECRET);
    return jwt_info;
}


exports.refresh_token = function(token) {
    // Refresh Token if the token hasn't expired.
    let result = jwt.decode(token, process.env.TOKEN_SECRET, algorithms = ["HS256"], function(err, decoded) {
        if (err) {
            /*
              err = {
                name: 'JsonWebTokenError',
                message: 'jwt malformed'
              }
            */
            return { "status": False, "data": None, "message": "Unable to decode data !" };
        }
    });
    let jwt_info = jwt.sign({ result, "exp": Date.now() + 300 },
        process.env.TOKEN_SECRET,
        function(err, decoded) {
            if (err) {
                /*
                  err = {
                    name: 'TokenExpiredError',
                    message: 'jwt expired',
                    expiredAt: 1408621000
                  }
                */
                return { "status": False, "data": None, "message": "Token has expired !" }
            }
        });

    return { "status": True, "data": jwt_info, "message": None }

}