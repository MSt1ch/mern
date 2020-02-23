const jwt = require('jsonwebtoken')
const config = require('config')

module.exports = (req, res, next) => {
    if (req.method === "OPTIONS") {
        return next();
    };

    try {

        const token = req.headers.authorization.split(" ")[1]; // "bearer TOKEN"
        console.log(jwt.verify(token, config.get("jwtSecret")));
        
        if (!token) {
            return res.status(401).json({ message: "No authrization" });
        }

        const decoded = jwt.verify(token, config.get("jwtSecret"));
        
        req.user = decoded;
        
        
        next();

    } catch(e) {
        res.status(401).json({ message: "No authorization" });
    }
}