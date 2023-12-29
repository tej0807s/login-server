
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const mailGen = require('mailgen')

require('dotenv').config();

const app = express();
app.use(bodyParser.json());

app.use(cors({
    origin: 'http://192.168.1.11:3000',
    methods: 'GET,POST,PUT,DELETE',
    allowedHeaders: 'Content-Type,Authorization',
    credentials: true,
    exposedHeaders: 'X-Custom-Header',
}));



// MongoDB Connection

const mongodbURL = process.env.DB_URL;

mongoose.connect(mongodbURL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 30000,
});


// Create databse Sachema

const UserData = mongoose.model('UserData', new mongoose.Schema({
    fullname: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    nickname: { type: String, required: true },
    email: { type: String, required: true }, // unique: true
    address: { type: String, required: true },
    nationality: { type: String, required: true },
    zipcode: { type: String, required: true },
    occupation: { type: String, required: true },
    about: { type: String, required: true },
    gender: { type: String, required: true },
    isAdmin: { type: Boolean, default: false } // Add this field
}));


// Secure Route

const jwt_key = process.env.JWT_KEY;

const requireUserAuth = (req, res, next) => {
    const token = req.header('Authorization') ? req.header('Authorization').replace('Bearer ', '') : null;

    if (!token) {
        return res.status(401).json({ message: 'Access denied! No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, jwt_key);
        req.user = decoded;
        next();
    } catch (error) {
        console.error(error);
        return res.status(400).json({ message: 'Invalid token.' });
    }
};

// Save Data into the database

app.post('/api/otherinfo', async (req, res) => {
    try {
        const { fullname, username, password, nickname, email, address, nationality, zipcode, occupation, about, gender } = req.body;
        const formData = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new UserData({ fullname, username, password: hashedPassword, nickname, email, address, nationality, zipcode, occupation, about, gender })
        await user.save();

        // Sending Emails
        
        const mailGenerator = new mailGen({
            theme: 'cerberus',
            product: {
                name: 'QuanticEdge Solution',
                link: 'https://quanticedgesolutions.com/',
            },
        });

        const emailTemplate = {
            body: {
                name: formData.fullname,
                intro: 'Welcome to the QuanticEdge Solution .',
                table: {
                    data: [
                        {
                            key: 'Username:',
                            value: formData.username
                        },
                        {
                            key: 'Email:',
                            value: formData.email
                        },
                        {
                            key: 'Address:',
                            value: formData.address
                        },
                        {
                            key: 'Nationality:',
                            value: formData.nationality
                        },
                        {
                            key: 'Zipcode:',
                            value: formData.zipcode
                        },
                        {
                            key: 'Occupation:',
                            value: formData.occupation
                        },
                        {
                            key: 'About:',
                            value: formData.about
                        },
                        {
                            key: 'Gender:',
                            value: formData.gender
                        }
                    ]
                }
            }
        };


        const defaultEmailTemplate = {
            body: {
                name: 'Admin',
                intro: 'The New Form is Submitted',
                table: {
                    data: [
                        {
                            key: 'Username:',
                            value: formData.username
                        },
                        {
                            key: 'Email:',
                            value: formData.email
                        },
                        {
                            key: 'Address:',
                            value: formData.address
                        },
                        {
                            key: 'Nationality:',
                            value: formData.nationality
                        },
                        {
                            key: 'Zipcode:',
                            value: formData.zipcode
                        },
                        {
                            key: 'Occupation:',
                            value: formData.occupation
                        },
                        {
                            key: 'About:',
                            value: formData.about
                        },
                        {
                            key: 'Gender:',
                            value: formData.gender
                        }
                    ]
                }
            }
        };
       

        const adminEmail = 'tejas.kumbhani@quanticedge.co.in';

        const adminTranspoter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 465,
            secure: true, // upgrade later to 587 secure with STARTTLS
            auth: {
                user: process.env.EMAIL,
                pass: process.env.PASSWORD
            }
        });

        const emailBodies = [
            { email: formData.email, body: emailTemplate },
            { email: adminEmail, body: defaultEmailTemplate }
        ];


        for (const emailBody of emailBodies) {
            const email = emailBody.email;
            const emailTemplate = emailBody.body;
            const emailBodyHtml = mailGenerator.generate(emailTemplate);

            const mailOptions = {
                from: 'quanticedge07@gmail.com',
                to: email,
                subject: 'Welcome to QuanticEdge Solution',
                html: emailBodyHtml
            };

            adminTranspoter.sendMail(mailOptions, function (error, info) {
                if (error) {
                    console.log(error);
                } else {
                    console.log('Email sent: ' + info.response);
                }
            });
        }

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        if (error.code === 11000 && error.keyPattern.email) {
            res.status(400).json({ message: 'Email is already in Use' });
        } else {
            console.error(error);
            res.status(500).json({ message: 'Registration failed' });
        }
    }
})

// Login Validation 

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await UserData.findOne({ email });

        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        const token = jwt.sign({ id: user._id, email: user.email }, jwt_key, { expiresIn: '1d' });
        const fullName = user.fullname;
        const admin = user.isAdmin || false;

        res.status(200).json({ message: 'Login successful', token, fullName, admin });
    } catch (error) {
        console.error(error);
        res.status(401).json({ message: 'Invalid email or password' });
    }
});


// Get All data from the Databse

app.get('/api/getAllData', requireUserAuth, async (req, res) => {
    try {
        const userId = req.user.id;
        const user = await UserData.findOne({ _id: userId });

        if (user) {
            if (user.isAdmin) {
                // If the user is an admin, return all data
                const allUsers = await UserData.find();
                res.send({ status: "ok", data: allUsers });
            } else {
                // If the user is not an admin, return only their own data
                res.send({ status: "ok", data: [user] });
            }
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error fetching data from the database' });
    }
});


// Delete data from the databse

app.delete('/api/deleteData/:id', async (req, res) => {
    const { id } = req.params; // Get the id from the URL parameters
    try {
        // Use Mongoose to find the user by ID and delete it
        await UserData.findOneAndDelete({ _id: id });
        res.send({ status: 'Ok', data: 'Deleted' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error deleting user' });
    }
});


const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});