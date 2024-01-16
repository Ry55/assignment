const express = require('express');
const session = require('express-session');
const app = express();
const port = process.env.PORT || 3000;

// json middleware
app.use(express.json());

// connect to mongodb
const {
    MongoClient
} = require('mongodb'); // import the mongodb client
const url = process.env.URL || "mongodb+srv://rruyingg:200105054130@cluster0.cwvxo8n.mongodb.net/"; // the url to the database
const client = new MongoClient(url); // create a new mongodb client

//unique session id generator middleware
const {
    v4: uuidv4
} = require('uuid');

//connect-mongo session middleware
const MongoStore = require('connect-mongo');
const store = MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    dbName: "Assignment",
    collectionName: "Sessions",
    ttl: 60 * 60 * 24, // 1 day
});

// session middleware
app.use(session({
    //generate unique session id
    genid: (req) => {
        return uuidv4()
    },
    secret: process.env.SECRET || "supercalifragilisticexpialidocious", // a random string used for encryption
    resave: false, // don't save session if unmodified
    saveUninitialized: false, // don't create session until something stored
    cookie: {
        maxAge: 1000 * 60 * 60, // 1 hour
        httpOnly:true,
        sameSite:"strict"
    },
    store:store
}));

//check and refresh the session
app.use((req, res, next) => {
    //check if the session is about to expire
    if (req.session) {
        if (req.session.cookie.maxAge < 1000 * 60 * 5) { // 5 minutes
            //refresh the session
            req.session.regenerate((err) => {
                if (err) {
                    res.send("Error refreshing session");
                } else {
                    next();
                }
            })
        } else {
            next();
        }
    } else {
        next();
    }
});

// bcrypt middleware
const bcrypt = require('bcryptjs') // to hash the password
const saltRounds = 13 // the higher the number the more secure, but slower

//password validator middleware
const passwordValidator = require('password-validator');
const schema = new passwordValidator();
schema
    .is().min(8, 'minimum length of 8 characters') // Minimum length 8
    .is().max(20, 'maximum length of 20 characters') // Maximum length 20
    .has().uppercase(1, 'minimum of 1 uppercase letter') // Must have uppercase letters
    .has().lowercase(1, 'minimum of 1 lowercase letter') // Must have lowercase letters
    .has().digits(1, 'minimum of 1 digit') // Must have digits
    .has().not().spaces(0, 'no spaces') // Should not have spaces
    .has().symbols(1, 'minimum of 1 symbol') // Must have symbols

// // qr code middleware
// var QRCode = require('qrcode')

// swagger middleware
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'MyVMS',
            version: '1.0.0',
        },
    },
    apis: ['./vms.js'],
};

// swagger docs
const specs = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

/**
 * @swagger
 * tags:
 *   - name: Test
 *   - name: Visitor
 *   - name: Login
 *   - name: Admin
 *   - name: Security
 *   - name: Resident
 */

async function run() {
    try {
        // Connect the client to the server
        await client.connect();

        // Send a ping to confirm a successful connection
        await client.db("admin").command({
            ping: 1
        });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");

        app.get('/', (req, res) => {
            res.redirect('/api-docs');
        });

        /**
         * @swagger
         * /login:
         *   post:
         *     tags:
         *       - Login
         *     description: Login to the system
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             properties:
         *               username:
         *                 type: string
         *               password:
         *                 type: string
         *     responses:
         *       '200':
         *         description: Connection successful
         */

        app.post('/login', async (req, res) => {
            let data = req.body;
        
            // check if user exists
            const result = await client.db("Assignment").collection("Users").findOne({
                _id: data.username
            });
        
            // if user exists, check if password is correct
            if (result) {
                if (await bcrypt.compare(data.password, result.password)) {
                    // if password is correct, create a session
                    console.log('Session ID before regeneration:', req.sessionID, req.session);
        
                    // regenerate session
                    req.session.regenerate(async (err) => {
                        if (err) {
                            res.send("Error regenerating session");
                        } else {
                            // store user details in session
                            req.session.user = {
                                name: result.name,
                                username: result._id,
                                role: result.role,
                                apartment: result.apartment
                            }
        
                            console.log('Session ID after regeneration:', req.sessionID, req.session);
        
                            if (req.session.user.role === "admin") {
                                try {
                                    const residents = await client.db("Assignment").collection("Users").aggregate([
                                        {
                                            $match: {
                                                role: "resident",
                                            }
                                        },
                                        {
                                            $sort: {
                                                _id: 1
                                            }
                                        },
                                        {
                                            $project: {
                                                _id: 1,
                                                name: 1,
                                                apartment: 1,
                                                mobile: 1,
                                            }
                                        }
                                    ]).toArray();

                                    const securities = await client.db("Assignment").collection("Users").aggregate([
                                        {
                                            $match: {
                                                role: "security",
                                            }
                                        },
                                        {
                                            $sort: {
                                                _id: 1
                                            }
                                        },
                                        {
                                            $project: {
                                                _id: 1,
                                                name: 1,
                                                mobile: 1,
                                            }
                                        }
                                    ]).toArray();
        
                                    res.send({
                                        to: req.session.user.name,
                                        message: 'Here are the list of all residents and securities: ',
                                        residents: residents,
                                        securities: securities
                                    });
                                } catch (e) {
                                    res.send("Error retrieving all residents");
                                }
                            } else {
                                res.send("Hello " + result.name);
                            }
                        }
                    });
                } else {
                    res.send("Wrong Password");
                }
            } else {
                res.send("Username not found");
            }
        });        

         /**
         * @swagger
         * /register/resident:
         *   post:
         *     tags:
         *       - Admin
         *       - Security
         *     description: Register a new resident
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             properties:
         *               _id:
         *                 type: string
         *               password:
         *                 description: Password must contain at least 8 characters, 1 uppercase letter, 1 lowercase letter, 1 digit, 1 symbol and no spaces
         *                 type: string
         *               name:
         *                 type: string
         *               apartment:
         *                 type: string
         *               mobile:
         *                 type: string
         *     responses:
         *       200:
         *         description: Connection successful
         */

        app.post('/register/resident', async (req, res) => {
            if (req.session.user)
                if (req.session.user.role == "admin" || req.session.user.role == "security") {
                    data = req.body;
                    try {
                        //check if user already exists
                        result = await client.db("Assignment").collection("Users").findOne({
                            _id: data._id,
                            role: "resident"
                        });

                        if (result) {
                            res.send("User already exists");
                        } else {
                            //validate password
                            const validation = schema.validate(data.password, {
                                details: true
                            });

                            if (validation.length > 0) {
                                errorMessages = validation.map((detail) => detail.message).join('\n');
                                res.send("Password does not meet the following requirements: \n" + errorMessages);
                            }
                            else {
                                //hash password
                                const hashedPassword = await bcrypt.hash(data.password, saltRounds);

                                // Validate if users insert a non-number for id, apartment, or mobile
                                if (!/^\d+$/.test(data._id) || !/^\d+$/.test(data.apartment) || !/^\d+$/.test(data.mobile)) {
                                    res.send("Please insert a valid number for id, apartment and mobile");
                                }
                                // Validate if users insert a non-alphabetic value for name
                                else if (!/^[a-zA-Z]+(?: [a-zA-Z]+)?$/.test(data.name)) {
                                    res.send("Please insert a valid name containing alphabets only");
                                }
                                else {
                                    //insert user
                                    const result = await client.db("Assignment").collection("Users").insertOne({
                                        _id: data._id,
                                        password: hashedPassword,
                                        role: "resident",
                                        name: data.name,
                                        apartment: data.apartment,
                                        mobile: data.mobile,
                                        pendingvisitors: [],
                                        incomingvisitors: [],
                                        pastvisitors: [],
                                        blockedvisitors: []
                                    });

                                    res.send('New resident created with the following id: ' + result.insertedId);
                                }
                            }
                        }
                    } catch (e) {
                        res.send("Error creating new resident");
                    }
                } else {
                    res.send("You do not have the previlege to create a new resident");
                }
            else {
                res.send("You are not logged in");
            }
        });

        /**
         * @swagger
         * /register/test/resident:
         *   post:
         *     tags:
         *       - Test
         *     description: Register a new resident without admin approval
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             properties:
         *               _id:
         *                 type: string
         *               password:
         *                 description: Password must contain at least 8 characters, 1 uppercase letter, 1 lowercase letter, 1 digit, 1 symbol and no spaces
         *                 type: string
         *               name:
         *                 type: string
         *               apartment:
         *                 type: string
         *               mobile:
         *                 type: string
         *     responses:
         *       200:
         *         description: Connection successful
         */


        app.post('/register/test/resident', async (req, res) => {
            data = req.body;
            try {
                //check if user already exists
                result = await client.db("Assignment").collection("Users").findOne({
                    _id: data._id,
                    role: "resident"
                });

                if (result) {
                    res.send("User already exists");
                } 
                else {
                    //validate password
                    const validation = schema.validate(data.password, {
                        details: true
                    });

                    if (validation.length > 0) {
                        errorMessages = validation.map((detail) => detail.message).join('\n');
                        res.send("Password does not meet the following requirements: \n" + errorMessages);
                    } 
                    else {
                        //hash password
                        const hashedPassword = await bcrypt.hash(data.password, saltRounds);

                        // Validate if users insert a non-number for id, apartment, or mobile
                        if (!/^\d+$/.test(data._id) || !/^\d+$/.test(data.apartment) || !/^\d+$/.test(data.mobile)) {
                            res.send("Please insert a valid number for id, apartment and mobile");
                        }
                        // Validate if users insert a non-alphabetic value for name
                        else if (!/^[a-zA-Z]+(?: [a-zA-Z]+)?$/.test(data.name)) {
                            res.send("Please insert a valid name containing alphabets only");
                        }
                        else {
                            //insert user
                            const result = await client.db("Assignment").collection("Users").insertOne({
                                _id: data._id,
                                password: hashedPassword,
                                role: "resident",
                                name: data.name,
                                apartment: data.apartment,
                                mobile: data.mobile,
                                pendingvisitors: [],
                                incomingvisitors: [],
                                pastvisitors: [],
                                blockedvisitors: []
                            });

                            res.send('New resident created with the following id: ' + result.insertedId);
                        }
                    }
                }
            } catch (e) {
                res.send("Error creating new resident");
            }
                
        });

        /**
         * @swagger
         * /remove/resident:
         *   post:
         *     tags:
         *       - Admin
         *       - Security
         *     description: Remove a resident
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             properties:
         *               _id:
         *                 type: string
         *               apartment:
         *                 type: string
         *     responses:
         *       200:
         *         description: Connection successful
         */

        app.post('/remove/resident', async (req, res) => {
            if (req.session.user)
                if (req.session.user.role == "admin" || req.session.user.role == "security") {
                    data = req.body;
                    try {
                        //check if user already exists
                        result = await client.db("Assignment").collection("Users").findOne({
                            _id: data._id,
                            role: "resident"
                        });

                        if (result) {
                            //remove user
                            const result = await client.db("Assignment").collection("Users").deleteOne({
                                _id: data._id,
                                role: "resident"
                            });

                            res.send('Resident with the following id: ' + data._id + " has been removed");
                        } else {
                            res.send("User does not exist");
                        }
                    } catch (e) {
                        res.send("Error removing resident");
                    }
                } else {
                    res.send("You do not have the previlege to remove a resident");
                }
            else {
                res.send("You are not logged in");
            }
        });

        /**
         * @swagger
         * /register/security:
         *   post:
         *     tags:
         *       - Admin
         *     description: Register a new security
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             properties:
         *               _id:
         *                 type: string
         *               password:
         *                 description: Password must contain at least 8 characters, 1 uppercase letter, 1 lowercase letter, 1 digit, 1 symbol and no spaces
         *                 type: string
         *               name:
         *                 type: string
         *               mobile:
         *                 type: string
         *     responses:
         *       200:
         *         description: Connection successful
         */

        app.post('/register/security', async (req, res) => {
            if (req.session.user)
                if (req.session.user.role == "admin") {
                    data = req.body;
                    try {
                        //check if user already exists
                        result = await client.db("Assignment").collection("Users").findOne({
                            _id: data._id,
                            role: "security"
                        });

                        if (result) {
                            res.send("User already exists");
                        } 
                        else {
                            //validate password
                            const validation = schema.validate(data.password, {
                                details: true
                            });

                            if (validation.length > 0) {
                                errorMessages = validation.map((detail) => detail.message).join('\n');
                                res.send("Password does not meet the following requirements: \n" + errorMessages);
                            } 
                            else {
                                //hash password
                                const hashedPassword = await bcrypt.hash(data.password, saltRounds);

                                // Validate if users insert a non-number for id and mobile
                                if (!/^\d+$/.test(data._id) || !/^\d+$/.test(data.mobile)) {
                                    res.send("Please insert a valid number for id and mobile");
                                }
                                // Validate if users insert a non-alphabetic value for name
                                else if (!/^[a-zA-Z]+(?: [a-zA-Z]+)?$/.test(data.name)) {
                                    res.send("Please insert a valid name containing alphabets only");
                                }
                                else {
                                    //insert user
                                    const result = await client.db("Assignment").collection("Users").insertOne({
                                        _id: data._id,
                                        password: hashedPassword,
                                        role: "security",
                                        name: data.name,
                                        mobile: data.mobile
                                    });

                                    res.send('New security created with the following id: ' + result.insertedId);
                                }
                            }
                        }
                    } catch (e) {
                        res.send("Error creating new security");
                    }
                } else {
                    res.send("You do not have the previlege to create a new security");
                }
            else {
                res.send("You are not logged in");
            }
        });

        /**
         * @swagger
         * /remove/security:
         *   post:
         *     tags:
         *       - Admin
         *     description: Remove a resident
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             properties:
         *               _id:
         *                 type: string
         *     responses:
         *       200:
         *         description: Connection successful
         */

        app.post('/remove/security', async (req, res) => {
            if (req.session.user)
                if (req.session.user.role == "admin") {
                    data = req.body;
                    try {
                        //check if user already exists
                        result = await client.db("Assignment").collection("Users").findOne({
                            _id: data._id,
                            role: "security"
                        });

                        if (result) {
                            //remove user
                            const result = await client.db("Assignment").collection("Users").deleteOne({
                                _id: data._id,
                                role: "security"
                            });

                            res.send('Security with the following id: ' + data._id + " has been removed");
                        } else {
                            res.send("User does not exist");
                        }
                    } catch (e) {
                        res.send("Error removing security");
                    }
                } else {
                    res.send("You do not have the previlege to remove a security");
                }
            else {
                res.send("You are not logged in");
            }
        });

        /**
         * @swagger
         * /visitor/new:
         *   post:
         *     tags:
         *       - Visitor
         *     description: Create a new visitor
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             properties:
         *               apartment:
         *                 type: string
         *               name:
         *                 type: string
         *               carplate:
         *                 type: string
         *               identification:
         *                 type: string
         *               mobile:
         *                 type: string
         *               visitpurpose:
         *                 type: string
         *     responses:
         *       '200':
         *         description: Connection successful
         */


        app.post('/visitor/new', async (req, res) => {
            req.body._id = visitoridgenerator();
            req.body.status = "pending";
            data = req.body;
            try {
                // add visitor to host's pending visitors
                await client.db("Assignment").collection("Users").updateOne({
                    _id: data.host,
                    apartment: data.apartment
                }, {
                    $push: {
                        pendingvisitors: req.body._id
                    }
                });

                // Validate if users insert a non-number for identification, or mobile
                if (!/^\d+$/.test(data.identification) || !/^\d+$/.test(data.mobile)) {
                    res.send("Please insert a valid number for identification and mobile");
                }
                // Ensure carplate is a combination of alphabet and number without symbols
                else if (!/^[A-Za-z]+\d*$/.test(data.carplate)) {
                    res.send("Please insert a valid carplate containing alphabets and numbers");
                }
                // Validate if users insert a non-alphabetic value for name
                else if (!/^[a-zA-Z]+$/.test(data.name)) {
                    res.send("Please insert an alphabet for name");
                }
                else {
                    // insert visitor into database
                    const result = await client.db("Assignment").collection("Visitors").insertOne(data);

                    res.send({
                        "message": "Your visitor request has been submitted, Please wait for approval from your host.",
                        "visitorid": data._id,
                        "apartment": data.apartment,
                        "name": data.name,
                        "carplate": data.carplate,
                        "identification": data.identification,
                        "mobile": data.mobile,
                        "visitpurpose": data.visitpurpose,
                    });
                }

                // // generate QR code
                // QRCode.toDataURL(data._id, (err, url) => {
                //     if (err) {
                //         res.send('Error generating QR code');
                //     } else {
                //         res.send({
                //             "message": "Your visitor request has been submitted, Please wait for approval from your host.",
                //             "qrcode": url,
                //             "visitorid": data._id,
                //             "apartment": data.apartment,
                //             "name": data.name,
                //             "carplate": data.carplate,
                //             "identification": data.identification,
                //             "mobile": data.mobile,
                //             "visitpurpose": data.visitpurpose,
                //         });
                //     }
                // });

                // // generate QR code
                // QRCode.toString(data._id, {
                //     type: "utf8"
                // }, (err, string) => {
                //     if (err) {
                //         res.send('Error generating QR code');
                //     } else {
                //         // Send the QR code as a response
                //         // Add spacing between each line
                //         const lines = string.split('\n');
                //         const spacedString = lines.join('                                   ');
                //         res.send({
                //             "message": "Your visitor request has been submitted with the following id: " + result.insertedId + ". Please wait for approval from your host.",
                //             // "qrcode": string,
                //             "qrcode": spacedString,
                //             "visitorid": data._id,
                //             "apartment": data.apartment,
                //             "name": data.name,
                //             "carplate": data.carplate,
                //             "identification": data.identification,
                //             "mobile": data.mobile,
                //             "visitpurpose": data.visitpurpose,
                //         });
                //     }
                // });
            } catch (e) {
                res.send("Error creating new listing, apartment not found");
            }
        });

        /**
         * @swagger
         * /visitor/status:
         *   post:
         *     tags:
         *       - Visitor
         *     description: Check visitor status
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             properties:
         *               _id:
         *                 type: string
         *     responses:
         *       '200':
         *         description: Connection successful
         */

        app.post('/visitor/status', async (req, res) => {
            data = req.body;
            result = await client.db("Assignment").collection("Visitors").findOne({
                _id: data._id
            });

            if (result) {
                if (result.status == "pending") {
                    res.send("Your visitor request is still pending. Please wait for approval from your host.");
                }

                if (result.status == "approved") {
                    res.send("Your visitor request has been approved. Please proceed to the security guard house to register your visit.");
                }

                if (result.status == "rejected") {
                    res.send("Your visitor request has been rejected. Please contact your host for more information.");
                }
            } else {
                res.send("Visitor not found");
            }
        });

        /**
         * @swagger
         * /dashboard:
         *   get:
         *     tags:
         *       - Admin
         *       - Security
         *       - Resident
         *     description: Retrieve all visitors
         *     responses:
         *       '200':
         *         description: Connection successful
         */

        app.get('/dashboard', async (req, res) => {
            if (req.session.user) {
                if (req.session.user.role == "security" || req.session.user.role == "admin") {
                    try {
                        result = await client.db("Assignment").collection("Visitors").aggregate([
                            {
                                $sort: {
                                    _id: -1
                                }
                            },
                            {
                                $project: {
                                    _id: 1,
                                    apartment: 1,
                                    name: 1,
                                    carplate: 1,
                                    identification: 1,
                                    mobile: 1,
                                    visitpurpose: 1,
                                    status: 1,
                                    reason: 1,
                                    checkin: 1,
                                    checkout: 1
                                }
                            }
                        ]).toArray();

                        res.send({
                            to: req.session.user.name,
                            message: 'Here are the list of all visitors: ',
                            visitors: result
                        });
                    } catch (e) {
                        res.send("Error retrieving pending visitors");
                    }
                } else if (req.session.user && req.session.user.role == "resident") {
                    try {
                        // list all pending visitors
                        result = await client.db("Assignment").collection("Visitors").aggregate([                            {
                                $sort: {
                                    _id: -1
                                }
                            },
                            {
                                $project: {
                                    _id: 1,
                                    name: 1,
                                    carplate: 1,
                                    identification: 1,
                                    mobile: 1,
                                    visitpurpose: 1,
                                    status: 1,
                                    reason: 1,
                                    checkin: 1,
                                    checkout: 1
                                }
                            }
                        ]).toArray();

                        res.send({
                            to: req.session.user.name,
                            message: 'Here are the list of your visitors: ',
                            visitors: result
                        });
                    } catch (e) {
                        res.send("Error retrieving pending visitors");
                    }
                } else {
                    res.send("You do not have the previlege to view pending visitors");
                }
            } else {
                res.send("You are not logged in");
            }
        });

        /**
         * @swagger
         * /dashboard/pending:
         *   get:
         *     tags:
         *       - Admin
         *       - Security
         *       - Resident
         *     description: Retrieve all pending visitors
         *     responses:
         *       '200':
         *         description: Connection successful
         */

        app.get('/dashboard/pending', async (req, res) => {
            if (req.session.user) {
                if (req.session.user.role == "security" || req.session.user.role == "admin") {
                    try {
                        result = await client.db("Assignment").collection("Visitors").aggregate([{
                                $match: {
                                    status: "pending",
                                }
                            },
                            {
                                $sort: {
                                    _id: -1
                                }
                            },
                            {
                                $project: {
                                    _id: 1,
                                    apartment: 1,
                                    name: 1,
                                    carplate: 1,
                                    identification: 1,
                                    mobile: 1,
                                    visitpurpose: 1,
                                }
                            }
                        ]).toArray();

                        res.send({
                            to: req.session.user.name,
                            message: "Here are the list of all pending visitors: ",
                            visitors: result
                        });
                    } catch (e) {
                        res.send("Error retrieving pending visitors");
                    }
                } else if (req.session.user && req.session.user.role == "resident") {
                    try {
                        // list all pending visitors
                        result = await client.db("Assignment").collection("Visitors").aggregate([{
                                $match: {
                                    apartment: req.session.user.apartment,
                                    status: "pending"
                                }
                            },
                            {
                                $sort: {
                                    _id: -1
                                }
                            },
                            {
                                $project: {
                                    _id: 1,
                                    name: 1,
                                    carplate: 1,
                                    identification: 1,
                                    mobile: 1,
                                    visitpurpose: 1,
                                }
                            }
                        ]).toArray();

                        res.send({
                            to: req.session.user.name,
                            message: "Here are the list of your pending visitors: ",
                            visitors: result
                        });
                    } catch (e) {
                        res.send("Error retrieving pending visitors");
                    }
                } else {
                    res.send("You do not have the previlege to view pending visitors");
                }
            } else {
                res.send("You are not logged in");
            }
        });

        /**
         * @swagger
         * /dashboard/approved:
         *   get:
         *     tags:
         *       - Admin
         *       - Security
         *       - Resident
         *     description: Retrieve all approved visitors
         *     responses:
         *       '200':
         *         description: Connection successful
         */

        app.get('/dashboard/approved', async (req, res) => {
            if (req.session.user) {
                if (req.session.user.role == "security" || req.session.user.role == "admin") {
                    try {
                        result = await client.db("Assignment").collection("Visitors").aggregate([{
                                $match: {
                                    status: "approved",
                                }
                            },
                            {
                                $sort: {
                                    _id: -1
                                }
                            },
                            {
                                $project: {
                                    _id: 1,
                                    apartment: 1,
                                    name: 1,
                                    carplate: 1,
                                    identification: 1,
                                    mobile: 1,
                                    visitpurpose: 1,
                                }
                            }
                        ]).toArray();

                        res.send({
                            to: req.session.user.name,
                            message: "Here are the list of all approved visitors: ",
                            visitors: result
                        });
                    } catch (e) {
                        res.send("Error retrieving approved visitors");
                    }
                } else if (req.session.user && req.session.user.role == "resident") {
                    try {
                        result = await client.db("Assignment").collection("Visitors").aggregate([{
                                $match: {
                                    host: req.session.user.username,
                                    status: "approved"
                                }
                            },
                            {
                                $sort: {
                                    _id: -1
                                }
                            },
                            {
                                $project: {
                                    _id: 1,
                                    name: 1,
                                    carplate: 1,
                                    identification: 1,
                                    mobile: 1,
                                    visitpurpose: 1,
                                }
                            }
                        ]).toArray();

                        res.send({
                            to: req.session.user.name,
                            message: "Gere are the list of your approved visitors: ",
                            visitors: result
                        });
                    } catch (e) {
                        res.send("Error retrieving approved visitors");
                    }
                } else {
                    res.send("You do not have the previlege to view approved visitors");
                }
            } else {
                res.send("You are not logged in");
            }
        });

        /**
         * @swagger
         * /dashboard/rejected:
         *   get:
         *     tags:
         *       - Admin
         *       - Security
         *       - Resident
         *     description: Retrieve all rejected visitors
         *     responses:
         *       '200':
         *         description: Connection successful
         */


        app.get('/dashboard/rejected', async (req, res) => {
            if (req.session.user) {
                if (req.session.user.role == "security" || req.session.user.role == "admin") {
                    try {
                        result = await client.db("Assignment").collection("Visitors").aggregate([{
                                $match: {
                                    status: "rejected",
                                }
                            },
                            {
                                $sort: {
                                    _id: -1
                                }
                            },
                            {
                                $project: {
                                    _id: 1,
                                    apartment: 1,
                                    name: 1,
                                    carplate: 1,
                                    identification: 1,
                                    mobile: 1,
                                    visitpurpose: 1,
                                    reason: 1
                                }
                            }
                        ]).toArray();

                        res.send({
                            to: req.session.user.name,
                            message: "Here are the list of all rejected visitors: ",
                            visitors: result
                        });
                    } catch (e) {
                        res.send("Error retrieving rejected visitors");
                    }
                } else if (req.session.user && req.session.user.role == "resident") {
                    try {
                        result = await client.db("Assignment").collection("Visitors").find({
                            host: req.session.user.username,
                            status: "rejected"
                        }).toArray();

                        result = await client.db("Assignment").collection("Visitors").aggregate([{
                                $match: {
                                    host: req.session.user.username,
                                    status: "rejected"
                                }
                            },
                            {
                                $sort: {
                                    _id: -1
                                }
                            },
                            {
                                $project: {
                                    _id: 1,
                                    name: 1,
                                    carplate: 1,
                                    identification: 1,
                                    mobile: 1,
                                    visitpurpose: 1,
                                    reason: 1
                                }
                            }
                        ]).toArray();

                        res.send({
                            to: req.session.user.name,
                            message: "Here are the list of your rejected visitors: ",
                            visitors: result
                        });
                    } catch (e) {
                        res.send("Error retrieving rejected visitors");
                    }
                } else {
                    res.send("You do not have the previlege to view rejected visitors");
                }
            } else {
                res.send("You are not logged in");
            }
        });

       /**
         * @swagger
         * /dashboard/history:
         *   get:
         *     tags:
         *       - Admin
         *       - Security
         *       - Resident
         *     description: Retrieve all past visitors
         *     responses:
         *       '200':
         *         description: Connection successful
         */

        app.get('/dashboard/history', async (req, res) => {
            if (req.session.user) {
                if (req.session.user.role == "security" || req.session.user.role == "admin") {
                    try {
                        result = await client.db("Assignment").collection("Visitors").aggregate([{
                                $match: {
                                    status: "checkedout"
                                }
                            },
                            {
                                $sort: {
                                    _id: -1
                                }
                            },
                            {
                                $project: {
                                    _id: 1,
                                    apartment: 1,
                                    name: 1,
                                    carplate: 1,
                                    identification: 1,
                                    mobile: 1,
                                    visitpurpose: 1,
                                    checkin: 1,
                                    checkout: 1
                                }
                            }
                        ]).toArray();

                        res.send({
                            to: req.session.user.name,
                            message: "Here are the list of all past visitors: ",
                            visitors: result

                        });
                    } catch (e) {
                        res.send("Error retrieving history");
                    }
                } else if (req.session.user.role == "resident") {
                    try {
                        result = await client.db("Assignment").collection("Visitors").aggregate([{
                                $match: {
                                    host: req.session.user.username,
                                    status: "checkedout"
                                }
                            },
                            {
                                $sort: {
                                    _id: -1
                                }
                            },
                            {
                                $project: {
                                    _id: 1,
                                    name: 1,
                                    carplate: 1,
                                    identification: 1,
                                    mobile: 1,
                                    visitpurpose: 1,
                                    checkin: 1,
                                    checkout: 1
                                }
                            }
                        ]).toArray();

                        res.send({
                            to: req.session.user.name,
                            message: "Here are the list of your past visitors: ",
                            visitors: result
                        });
                    } catch (e) {
                        res.send("Error retrieving history");
                    }
                } else {
                    res.send("You do not have the previlege to view history");
                }
            } else {
                res.send("You are not logged in");
            }
        });
        
        /**
         * @swagger
         * /dashboard/create:
         *   post:
         *     tags:
         *       - Resident
         *     description: Create a new visitor invite
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             properties:
         *               apartment:
         *                 type: string
         *               name:
         *                 type: string
         *               carplate:
         *                 type: string
         *               identification:
         *                 type: string
         *               mobile:
         *                 type: string
         *               visitpurpose:
         *                 type: string
         *     responses:
         *       '200':
         *         description: Connection successful
         */

        app.post('/dashboard/create', async (req, res) => {
            if (req.session.user) {
                if (req.session.user.role == "resident") {
                    req.body._id = visitoridgenerator();
                    req.body.status = "approved";
                    req.body.apartment = req.session.user.apartment;
                    data = req.body;
                    try {
                        await client.db("Assignment").collection("Users").updateOne({
                            apartment: data.apartment
                        }, {
                            $push: {
                                incomingvisitors: req.body._id
                            }
                        });

                        const result = await client.db("Assignment").collection("Visitors").insertOne({
                            _id: data._id,
                            apartment: data.apartment,
                            name: data.name,
                            carplate: data.carplate,
                            identification: data.identification,
                            mobile: data.mobile,
                            visitpurpose: data.visitpurpose,
                            status: data.status
                        });

                        res.send({
                            "message": "You have created a new visitor invite, Please send the visitorid to your visitor.",
                            "visitorid": data._id,
                            "apartment": data.apartment,
                            "name": data.name,
                            "carplate": data.carplate,
                            "identification": data.identification,
                            "mobile": data.mobile,
                            "visitpurpose": data.visitpurpose,
                        });

                        // QRCode.toDataURL(data._id,(err, url) => {
                        //     if (err) {
                        //         res.send('Error generating QR code');
                        //     } else {
                        //         res.send({
                        //             "message": "You have created a new visitor invite, Please send the QR code to your visitor.",
                        //             "qrcode": url,
                        //             "visitorid": data._id,
                        //             "apartment": data.apartment,
                        //             "name": data.name,
                        //             "carplate": data.carplate,
                        //             "identification": data.identification,
                        //             "mobile": data.mobile,
                        //             "visitpurpose": data.visitpurpose,
                        //         });
                        //     }
                        // });

                        // QRCode.toString(data._id, {
                        //     type: "utf8"
                        // }, (err, string) => {
                        //     if (err) {
                        //         res.send('Error generating QR code');
                        //     } else {
                        //         // Send the QR code as a response
                        //         // Add spacing between each line
                        //         const lines = string.split('\n');
                        //         const spacedString = lines.join('                                   ');
                        //         res.send({
                        //             "message": "You have created a new visitor invite, Please send the QR code to your visitor.",
                        //             // "qrcode": string,
                        //             "qrcode": spacedString,
                        //             "visitorid": data._id,
                        //             "apartment": data.apartment,
                        //             "name": data.name,
                        //             "carplate": data.carplate,
                        //             "identification": data.identification,
                        //             "mobile": data.mobile,
                        //             "visitpurpose": data.visitpurpose,
                        //         });
                        //     }
                        // });
                    } catch (e) {
                        res.send("Error creating new listing,either host or apartment not found");
                    }
                } else {
                    res.send("You do not have the previlege to create a new visitor");
                }
            } else {
                res.send("You are not logged in");
            }
        });

        /**
         * @swagger
         * /dashboard/approve:
         *   post:
         *     tags:
         *       - Resident
         *     description: Approve a visitor
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             properties:
         *               _id:
         *                 type: string
         *     responses:
         *       '200':
         *         description: Connection successful
         */

        app.post('/dashboard/approve', async (req, res) => {
            if (req.session.user) {
                if (req.session.user.role == "resident") {
                    apartment = req.session.user.apartment;
                    data = req.body;
                    try {
                        //check if visitor exists
                        result = await client.db("Assignment").collection("Visitors").findOne({
                            _id: data._id
                        });

                        if (result) {
                            if (result.status == "pending" || result.status == "rejected") {

                                await client.db("Assignment").collection("Visitors").updateOne({
                                    _id: data._id
                                }, {
                                    $set: {
                                        status: "approved"
                                    },
                                    $unset: {
                                        reason: ""
                                    }
                                });

                                await client.db("Assignment").collection("Users").updateOne({
                                    apartment: apartment
                                }, {
                                    $pull: {
                                        pendingvisitors: data._id,
                                        blockedvisitors: data._id,
                                    },
                                    $push: {
                                        incomingvisitors: data._id
                                    }
                                });

                                res.send('Visitor with the id: ' + data._id + " has been approved");
                            } else {
                                res.send("Visitor is not pending");
                            }
                        } else {
                            res.send("Visitor not found");
                        }

                    } catch (e) {
                        res.send("Error approving visitor");
                    }
                } else {
                    res.send("You do not have the previlege to approve a visitor");
                }
            } else {
                res.send("You are not logged in");
            }
        });

        /**
         * @swagger
         * /dashboard/reject:
         *   post:
         *     tags:
         *       - Resident
         *     description: Reject a visitor
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             properties:
         *               _id:
         *                 type: string
         *               reason:
         *                 type: string
         *     responses:
         *       '200':
         *         description: Connection successful
         */

        app.post('/dashboard/reject', async (req, res) => {
            if (req.session.user) {
                if (req.session.user.role == "resident") {
                    apartment = req.session.user.apartment;
                    data = req.body;
                    try {
                        //check if visitor exists
                        result = await client.db("Assignment").collection("Visitors").findOne({
                            _id: data._id
                        });

                        if (result) {
                            if (result.status == "pending" || result.status == "approved") {
                                await client.db("Assignment").collection("Visitors").updateOne({
                                    _id: data._id
                                }, {
                                    $set: {
                                        status: "rejected"
                                    },
                                    $push: {
                                        reason: data.reason
                                    }
                                });

                                await client.db("Assignment").collection("Users").updateOne({
                                    apartment: apartment
                                }, {
                                    $pull: {
                                        pendingvisitors: data._id,
                                        incomingvisitors: data._id
                                    },
                                    $push: {
                                        blockedvisitors: data._id
                                    }
                                });

                                res.send('Visitor with the id: ' + data._id + " has been rejected");
                            } else {
                                res.send("Visitor is not pending or approved");
                            }
                        } else {
                            res.send("Visitor not found");
                        }

                    } catch (e) {
                        res.send("Error rejecting visitor");
                    }
                } else {
                    res.send("You do not have the previlege to reject a visitor");
                }
            } else {
                res.send("You are not logged in");
            }
        });

        /**
         * @swagger
         * /checkin:
         *   post:
         *     tags:
         *       - Security
         *     description: Check in a visitor
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             properties:
         *               _id:
         *                 type: string
         *     responses:
         *       '200':
         *         description: Connection successful
         */

        app.post('/checkin', async (req, res) => {
            if (req.session.user) {
                if (req.session.user.role == "security") {
                    data = req.body;
                    try {
                        //check if visitor exists
                        result = await client.db("Assignment").collection("Visitors").findOne({
                            _id: data._id
                        });

                        if (result) {
                            if (result.status == "approved") {
                                await client.db("Assignment").collection("Visitors").updateOne({
                                    _id: data._id
                                }, {
                                    $set: {
                                        status: "checkedin",
                                        checkin: getCurrentDateTime()
                                    }
                                });

                                res.send('Visitor with the id: ' + data._id + " has been checked in");
                            } else if (result.status == "pending"){
                                res.send("Visitor is not approved yet");
                            } else if (result.status == "rejected"){
                                res.send("Visitor is rejected");
                            }else {
                                res.send("Visitor is already checked in");
                            }
                        } else {
                            res.send("Visitor not found");
                        }

                    } catch (e) {
                        res.send("Error checking in visitor");
                    }
                } else {
                    res.send("You do not have the previlege to check in a visitor");
                }
            } else {
                res.send("You are not logged in");
            }
        });

        /**
         * @swagger
         * /checkout:
         *   post:
         *     tags:
         *       - Security
         *     description: Check out a visitor
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             properties:
         *               _id:
         *                 type: string
         *     responses:
         *       '200':
         *         description: Connection successful
         */

        app.post('/checkout', async (req, res) => {
            if (req.session.user) {
                if (req.session.user.role == "security") {
                    data = req.body;
                    try {
                        //check if visitor exists
                        result = await client.db("Assignment").collection("Visitors").findOne({
                            _id: data._id
                        });

                        if (result) {
                            if (result.status == "checkedin") {
                                await client.db("Assignment").collection("Visitors").updateOne({
                                    _id: data._id
                                }, {
                                    $set: {
                                        status: "checkedout",
                                        checkout: getCurrentDateTime()
                                    }
                                });

                                await client.db("Assignment").collection("Users").updateOne({
                                    _id: result.host,
                                    apartment: result.apartment
                                }, {
                                    $pull: {
                                        incomingvisitors: data._id
                                    },
                                    $push: {
                                        pastvisitors: data._id
                                    }
                                });

                                res.send('Visitor with the id: ' + data._id + " has been checked out");
                            } else {
                                res.send("Visitor is not checked in");
                            }
                        } else {
                            res.send("Visitor not found");
                        }

                    } catch (e) {
                        res.send("Error checking out visitor");
                    }
                } else {
                    res.send("You do not have the previlege to check out a visitor");
                }
            } else {
                res.send("You are not logged in");
            }
        });

        /**
         * @swagger
         * /checkVisitor:
         *   post:
         *     tags:
         *       - Security
         *     description: Check the information of the visitor and visitor's host
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             properties:
         *               _id:
         *                 type: string
         *     responses:
         *       '200':
         *         description: Connection successful
         */

        app.post('/checkVisitor', async (req, res) => {
            const data = req.body;
        
            try {
                const visitorResult = await client.db("Assignment").collection("Visitors").findOne({
                    _id: data._id
                });
        
                if (visitorResult) {
                    const visitorInfo = {
                        "message": "Visitor found",
                        "name": visitorResult.name,
                        "carplate": visitorResult.carplate,
                        "identification": visitorResult.identification,
                        "mobile": visitorResult.mobile,
                        "visitpurpose": visitorResult.visitpurpose,
                        "status": visitorResult.status
                    };
        
                    try {
                        const hostResult = await client.db("Assignment").collection("Users").findOne({
                            apartment: visitorResult.apartment
                        });
        
                        if (hostResult) {
                            const hostInfo = {
                                "message": "Here are the details of the host:",
                                "name": hostResult.name,
                                "apartment": hostResult.apartment,
                                "mobile": hostResult.mobile
                            };
        
                            const combinedInfo = {
                                visitor: visitorInfo,
                                host: hostInfo
                            };
        
                            res.send(combinedInfo);
                        } else {
                            res.send({
                                visitor: visitorInfo,
                                host: "Host not found"
                            });
                        }
                    } catch (error) {
                        res.send({
                            visitor: visitorInfo,
                            host: "Error retrieving host"
                        });
                    }
                } else {
                    res.send("Visitor not found");
                }
            } catch (err) {
                res.send("Error retrieving visitor");
            }
        });        

        /**
         * @swagger
         * /logout:
         *   get:
         *     tags:
         *       - Login
         *     description: Logout
         *     responses:
         *       '200':
         *         description: Connection successful
         */

        app.get('/logout', async (req, res) => {
            if (req.session.user) {
                req.session.destroy();
                res.send("You have been logged out");
            } else {
                res.send("You are not logged in");
            }
        });

        app.listen(port, () => {
            console.log(`Example app listening at http://localhost:${port}`)
        });

    } catch (e) {
        console.error(e);
    }
}

run().catch(console.error); // Run the async function

function getCurrentDateTime() {
    const currentDateTime = new Date();

    const year = currentDateTime.getFullYear();
    const month = String(currentDateTime.getMonth() + 1).padStart(2, '0');
    const day = String(currentDateTime.getDate()).padStart(2, '0');

    const hours = String(currentDateTime.getHours()).padStart(2, '0');
    const minutes = String(currentDateTime.getMinutes()).padStart(2, '0');
    const seconds = String(currentDateTime.getSeconds()).padStart(2, '0');

    const formattedDateTime = `${year}/${month}/${day} ${hours}:${minutes}:${seconds}`;

    return formattedDateTime;
}

function visitoridgenerator() {
    const currentDate = new Date();
    const year = currentDate.getFullYear();
    const month = String(currentDate.getMonth() + 1).padStart(2, '0');
    const day = String(currentDate.getDate()).padStart(2, '0');
    const hours = String(currentDate.getHours()).padStart(2, '0');
    const minutes = String(currentDate.getMinutes()).padStart(2, '0');
    const seconds = String(currentDate.getSeconds()).padStart(2, '0');
    const currentDateTimeString = `${year}${month}${day}${hours}${minutes}${seconds}`;
    return currentDateTimeString;
}
