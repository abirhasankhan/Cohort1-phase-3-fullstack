import User from "../model/User.model.js"
import crypto from "crypto"
import nodemailer from "nodemailer"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import dotenv from "dotenv"
dotenv.config()


const registerUser = async (req, res) => {
    
    // get data from req body

    const { name, email, password } = req.body || {};

    // validate data

    if(!name || !email || !password) {
        return res.status(400).json({
            message: "All fields are required"
        })
    }

    try {

        // check if user already exists

        const existingUser = await User.findOne({email})

        if(existingUser) {
            return res.status(400).json({
                message: "User already exists"
            })
        }


        // if not exists, create user

        const newUser = await User.create({
            name,
            email,
            password
        })

        if(!newUser) {
            return res.status(500).json({
                message: "User not registered"
            })
        }

        // generate token

        const token = crypto.randomBytes(32).toString("hex")
        // console.log(token);

        // save token in db
        newUser.verificationToken = token

        await newUser.save()


        // sent token as email to user
        // Create a test account or replace with real credentials.
        const transporter = nodemailer.createTransport({
            host: process.env.MAILTRAP_HOST,
            port: process.env.MAILTRAP_PORT,
            secure: false, // true for 465, false for other ports
            auth: {
                user: process.env.MAILTRAP_USER,
                pass: process.env.MAILTRAP_PASSWORD,
            },
        });

        const mailOption = {
            
            from: process.env.MAILTRAP_SENDERMAIL,
            to: newUser.email,
            subject: "Verify your email",
            text: `Please click the link to verify your email: ${process.env.BASE_URL}/api/v1/users/verify/${token}`,
        }

        await transporter.sendMail(mailOption)
        

        // send success status to user
        res.status(200).json({
            message: "User registered successfully",
            success: true
        })


    } catch (error) {

        res.status(400).json({
            message: "User not registered",
            error,
            success: false
        })
        
    }
    

}

const verifyUser = async (req, res) => {
    
    // get token from url
    // validate token
    // find user base on token
    // update user isVerified to true
    // remove verification token
    // saev
    // return response

    const { token } = req.params || {};
    
    console.log(token);
    if(!token) {
        return res.status(400).json({
            message: "Invalid token",
            success: false
        })
    }

    const user = await User.findOne({verificationToken: token})

    if(!user) {
        return res.status(400).json({
            message: "Invalid token",
            success: false
        })
    }

    user.isVerified = true
    user.verificationToken = null

    await user.save()
}

const login = async (req, res) => {

    const {email, password} = req.body || {}

    if (!email || !password) {
        return res.status(400).json({
            message: "All fields are required"
        })
    }

    try {

        const user = await User.findOne({email})

        if (!user) {
            return res.status(400).json({
                message: "Invalid email or password"
            })
        }

        const isMatch = await bcrypt.compare(password, user.password)


        console.log(isMatch);

        if (!isMatch) {
            return res.status(400).json({
                message: "Invalid email or password"
            })
        }

        // const verifyUser = await User.isVerified

        // if (!verifyUser) {
        //     return res.status(400).json({
        //         message: "user isn't verify yet"
        //     })
        // }

        const token = jwt.sign({id: user._id, role: user.role},
            process.env.JWT_TOKEN, {
                    expiresIn: '24h'
                }
            )

        const cookieOptions ={
            httpOnly: true,
            secure: true,
            maxAge: 24*60*60*1000
        }

        res.cookie("test", token, cookieOptions)

        res.status(200).json({
            success: true,
            message: "Login successful",
            token,
            user: {
                id: user._id,
                name: user.name,
                role: user.role
            }
        })
        

    } catch (error) {
        res.status(400).json({
            message: "Login error",
            error: error,
            success: false
        })
    }
}

export { registerUser, verifyUser, login }