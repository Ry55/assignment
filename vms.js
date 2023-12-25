const express = require('express');
const session = require('express-session');
const app = express();
const port = process.env.PORT||3000;

// session middleware
app.use(session({
    secret: 'supercalifragilisticexpialidocious', // a random string used for encryption
    resave: false, // don't save session if unmodified
    saveUninitialized: false // don't create session until something stored
}));

// json middleware
app.use(express.json());

// qr code middleware
var QRCode = require('qrcode')

// connect to mongodb
const {
    MongoClient
} = require('mongodb'); // import the mongodb client
const url = "mongodb+srv://rruyingg:200105054130@cluster0.cwvxo8n.mongodb.net/"; // the url to the database
const client = new MongoClient(url); // create a new mongodb client

// bcrypt middleware
const bcrypt = require('bcryptjs') // to hash the password
const saltRounds = 13 // the higher the number the more secure, but slower

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
            res.send('Hello World!')
        });

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
                    req.session.user = {
                        name: result.name,
                        username: result._id,
                        role: result.role,
                        apartment: result.apartment
                    }
                    console.log(req.session);
                    res.send("Hello " + result.name);
                } else {
                    res.send("Wrong Password");
                }
            } else {
                res.send("Username not found");
            }
        });

        app.post('/register/resident', async (req, res) => {
            if (req.session.user)
                if (req.session.user.role == "admin") {
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
                            //hash password
                            const hashedPassword = await bcrypt.hash(data.password, saltRounds);

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

        app.post('/remove/resident', async (req, res) => {
            if (req.session.user)
                if (req.session.user.role == "admin") {
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
                        } else {
                            //hash password
                            const hashedPassword = await bcrypt.hash(data.password, saltRounds);

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

                // insert visitor into database
                const result = await client.db("Assignment").collection("Visitors").insertOne(data);

                // generate QR code
                QRCode.toDataURL(data._id, (err, url) => {
                    if (err) {
                        res.send('Error generating QR code');
                    } else {
                        res.send({
                            "message": "Your visitor request has been submitted, Please wait for approval from your host.",
                            "qrcode": url,
                            "visitorid": data._id,
                            "host": data.host,
                            "apartment": data.apartment,
                            "name": data.name,
                            "carplate": data.carplate,
                            "identification": data.identification,
                            "mobile": data.mobile,
                            "visitpurpose": data.visitpurpose,
                        });
                    }
                });

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
                //             "host": data.host,
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
        });

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
                                    host: 1,
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
                                    host: 1,
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
                                    host: req.session.user.username,
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
                                    host: 1,
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
                                    host: 1,
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
                                    host: 1,
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

        app.post('/dashboard/create', async (req, res) => {
            if (req.session.user) {
                if (req.session.user.role == "resident") {
                    req.body._id = visitoridgenerator();
                    req.body.status = "approved";
                    req.body.host = req.session.user.username;
                    req.body.apartment = req.session.user.apartment;
                    data = req.body;
                    try {
                        await client.db("Assignment").collection("Users").updateOne({
                            _id: data.host,
                            apartment: data.apartment
                        }, {
                            $push: {
                                incomingvisitors: req.body._id
                            }
                        });

                        const result = await client.db("Assignment").collection("Visitors").insertOne({
                            _id: data._id,
                            host: data.host,
                            apartment: data.apartment,
                            name: data.name,
                            carplate: data.carplate,
                            identification: data.identification,
                            mobile: data.mobile,
                            visitpurpose: data.visitpurpose,
                            status: data.status
                        });

                        QRCode.toDataURL(data._id,(err, url) => {
                            if (err) {
                                res.send('Error generating QR code');
                            } else {
                                res.send({
                                    "message": "You have created a new visitor invite, Please send the QR code to your visitor.",
                                    "qrcode": url,
                                    "visitorid": data._id,
                                    "host": data.host,
                                    "apartment": data.apartment,
                                    "name": data.name,
                                    "carplate": data.carplate,
                                    "identification": data.identification,
                                    "mobile": data.mobile,
                                    "visitpurpose": data.visitpurpose,
                                });
                            }
                        });

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
                        //             "host": data.host,
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

        app.post('/dashboard/approve', async (req, res) => {
            if (req.session.user) {
                if (req.session.user.role == "resident") {
                    host = req.session.user.username;
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
                                    _id: host,
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

        app.post('/dashboard/reject', async (req, res) => {
            if (req.session.user) {
                if (req.session.user.role == "resident") {
                    host = req.session.user.username;
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
                                    _id: host,
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
                            } else {
                                res.send("Visitor is either not approved or already checked in");
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
