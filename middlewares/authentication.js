const { validateToken } = require("../services/authentication");

function checkForAuthenticationCookie(cookieName) {
    return (req, res, next) => {
        const tokenCookieValue = req.cookies[cookieName];

        if(!tokenCookieValue) {
           return next();
        }
        
       try {
            const userPayload = validateToken(tokenCookieValue);
            console.log(userPayload);   // <-- add this
            req.user = userPayload;
        } catch (error) {
            console.log(error);         // <-- don't leave catch empty
        }
         return next(); // return 
    };
}

module.exports ={
    checkForAuthenticationCookie,
}