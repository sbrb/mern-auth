const jwt = require("jsonwebtoken");
const userModel = require("../models/userSchema");
const secretKey = process.env.SECRET_KEY


const authenticate = async (req, res, next) => {

    try {
        const token = req.headers.authorization;
        const verifytoken = jwt.verify(token, secretKey);
        const rootUser = await userModel.findOne({ _id: verifytoken._id });

        if (!rootUser) { throw new Error("user not found") }
        req.token = token;
        req.rootUser = rootUser;
        req.userId = rootUser._id;
        next();

    } catch (error) {
        res.status(401).json({ status: 401, message: "Unauthorized no token provide" })
    }
}


module.exports = authenticate;