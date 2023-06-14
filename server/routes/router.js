const express = require("express");
const router = new express.Router();
const userModel = require("../models/userSchema");
const bcrypt = require("bcryptjs");
const authenticate = require("../middleware/authenticate");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");

const secretKey = process.env.SECRET_KEY;
const baseUrl = process.env.BASE_URL;


// email config
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD
    }
})


// for user registration
router.post("/register", async (req, res) => {

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        res.status(422).json({ error: "Fill all the details." })
    }

    try {
        const foundUser = await userModel.findOne({ email });

        if (foundUser) {
            res.status(422).json({ error: "This Email is Already Exist." })
        } else {
            const finalUser = new userModel({ name, email, password });
            console.log(finalUser)
            // password hashing
            const storeData = await finalUser.save();

            res.status(201).json({ status: 201, storeData })
        }
    } catch (error) {
        res.status(422).json(error.message);
        console.log(error);
    }
});




// user Login
router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        res.status(422).json({ error: "Fill All The Details" })
    }

    try {
        const validUser = await userModel.findOne({ email });

        if (validUser) {
            const isMatch = await bcrypt.compare(password, validUser.password);
            if (!isMatch) {
                res.status(422).json({ error: "Invalid Details." })
            } else {
                // token generate
                const token = await validUser.generateAuthToken();
                // cookie generate
                res.cookie("usercookie", token, {
                    expires: new Date(Date.now() + 9000000),
                    httpOnly: true
                });

                const result = { validUser, token };
                res.status(201).json({ status: 201, result })
            }
        } else {
            res.status(401).json({ status: 401, message: "Invalid Details." });
        }
    } catch (error) {
        console.log(error);
        res.status(401).json({ status: 401, error: error.message });
    }
});



// user valid
router.get("/validuser", authenticate, async (req, res) => {
    try {
        const validUserOne = await userModel.findOne({ _id: req.userId });
        res.status(201).json({ status: 201, validUserOne });
    } catch (error) {
        console.log(error);
        res.status(401).json({ status: 401, error: error.message });
    }
});


// user logout
router.get("/logout", authenticate, async (req, res) => {
    try {
        req.rootUser.tokens = req.rootUser.tokens.filter((ele) => {
            return ele.token !== req.token
        });
        res.clearCookie("usercookie", { path: "/" });
        req.rootUser.save();
        res.status(201).json({ status: 201 })
    } catch (error) {
        console.log(error);
        res.status(401).json({ status: 401, error: error.message });
    }
});



// send email Link For reset Password
router.post("/sendpasswordlink", async (req, res) => {

    const { email } = req.body;
    if (!email) {
        res.status(401).json({ status: 401, message: "Enter Your Email" })
    }
    try {
        const foundUser = await userModel.findOne({ email });
        // token generate for reset password
        const token = jwt.sign({ _id: foundUser._id }, secretKey, {
            expiresIn: "120s"
        });
        const setUserToken = await userModel.findByIdAndUpdate({ _id: foundUser._id }, { verifytoken: token }, { new: true });
        if (setUserToken) {
            const mailOptions = {
                from: process.env.EMAIL,
                to: email,
                subject: "Sending Email For password Reset",
                text: `This Link Valid For 2 MINUTES ${baseUrl}/forgotpassword/${foundUser.id}/${setUserToken.verifytoken}`
            }

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.log("error", error);
                    res.status(401).json({ status: 401, message: "email not send" })
                } else {
                    console.log("Email sent", info.response);
                    res.status(201).json({ status: 201, message: "Email sent Successfully." })
                }
            })
        }

    } catch (error) {
        console.log(error);
        res.status(401).json({ status: 401, error: error.message });
    }
});


// verify user for forgot password time
router.get("/forgotpassword/:id/:token", async (req, res) => {
    const { id, token } = req.params;
    try {
        const validUser = await userModel.findOne({ _id: id, verifytoken: token });
        const verifyToken = jwt.verify(token, secretKey);

        if (validUser && verifyToken._id) {
            res.status(201).json({ status: 201, validUser })
        } else {
            res.status(401).json({ status: 401, message: "User Does't exist." })
        }
    } catch (error) {
        console.log(error);
        res.status(401).json({ status: 401, error: error.message });
    }
});


// change password
router.post("/:id/:token", async (req, res) => {
    const { id, token } = req.params;
    const { password } = req.body;

    try {
        const validUser = await userModel.findOne({ _id: id, verifytoken: token });
        const verifyToken = jwt.verify(token, secretKey);

        if (validUser && verifyToken._id) {
            const newPassword = await bcrypt.hash(password, 12);
            const setNewUserPass = await userModel.findByIdAndUpdate({ _id: id }, { password: newPassword });

            setNewUserPass.save();
            res.status(201).json({ status: 201, setNewUserPass })
        } else {
            res.status(401).json({ status: 401, message: "User Does't exist." })
        }
    } catch (error) {
        console.log(error);
        res.status(401).json({ status: 401, error: error.message });
    }
})


module.exports = router;
