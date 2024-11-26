//to install required modules, in terminal: "npm i http ws express ejs sqlite3 crypto express-session"

const express = require("express"); //import express
const ejs = require("ejs"); //import ejs
const sqlite3 = require("sqlite3"); //import sqlite3
const crypto = require("crypto"); //import crypto
const session = require('express-session'); //import express-session

const app = express(); //initialize express with app

app.set("view engine", "ejs"); // set view engine
app.use(express.urlencoded({ extended: true })); //encode url

//allows calling of files in public folder
app.use(express.static("public"))

const sessionSecret = process.env.SESSION_SECRET || "defaultSecret";
app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false
}));

function isAuthenticated(req, res, next) {
    if (req.session.user) next()
    else res.redirect("/")
};

/*---------
HTTP Server
---------*/

const http = require('http').Server(app); //import http, create http server and associate it with express

const PORT = process.env.PORT || 3000; //change port number from default

/*--------------
WebSocket Server
--------------*/

const WebSocket = require("ws"); //import WebSocket
const wss = new WebSocket.Server({ server: http }); //create new WebSocket server, attach it to http server

function userList(wss) {
    let users = [];
    wss.clients.forEach(client => {
        if (client.user) {
            users.push(client.user);
        };
    });
    return { list: users };
};

function broadcast(wss, data) {
    const message = JSON.stringify(data);
    wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(message);
        };
    });
};

wss.on("connection", (client => { //on connection to server
    client.on("close", () => {
        console.log(`${client.user} has disconnected.`); //user disconnects
        broadcast(wss, userList(wss)); //broadcast updated userList
    });

    client.on("message", (data) => {
        const parsedMsg = JSON.parse(data); //parse incoming message

        if (parsedMsg.user) {
            client.user = parsedMsg.user;
            broadcast(wss, userList(wss)); //broadcast updated userList
        };
        if (parsedMsg.convo_id && parsedMsg.text) {
            // Save the message to the database
            db.run("INSERT INTO posts (convo_id, user, text, timestamp) VALUES (?, ?, ?, datetime('now'))", [parsedMsg.convo_id, parsedMsg.user, parsedMsg.text], (err) => {
                if (err) {
                    console.error("Error saving message to database:", err);
                    return;
                };

                //broadcast the message to all connected clients
                broadcast(wss, { convo_id: parsedMsg.convo_id, user: parsedMsg.user, text: parsedMsg.text });
            });
        };
    });
}));

/*-------------
Create Database
-------------*/

const db = new sqlite3.Database("data/database.db", (err) => {
    if (err) {
        console.log("Error opening database:", err);
        return; //exit if database can't be opened
    } else {
        console.log("Database connected successfully.");
        //start the server after the database is connected
        http.listen(PORT, () => {
            console.log(`Server started on port ${PORT}`);
        });
    }
});

/*---------------
GET/POST Requests
---------------*/

//handle index
app.get("/", (req, res) => {
    res.render("index");
});

app.post("/", (req, res) => {
    if (req.body.user && req.body.pass) {
        //users table
        db.get("SELECT * FROM users WHERE username=?;", req.body.user, (err, row) => {
            if (err) {
                console.log(err);
                res.send("There was an error:\n" + err);
            } else if (!row) {
                //Create a new salt for this user
                const salt = crypto.randomBytes(16).toString("hex");

                //Use the salt to "hash" the password
                crypto.pbkdf2(req.body.pass, salt, 1000, 64, "sha512", (err, derivedKey) => {
                    if (err) {
                        res.send("Error hashing password: " + err);
                    } else {
                        const hashedPassword = derivedKey.toString("hex");

                        db.run("INSERT INTO users (username, password, salt) VALUES (?, ?, ?);", [req.body.user, hashedPassword, salt], (err) => {
                            if (err) {
                                res.send("Database error: \n" + err);
                            } else {
                                res.send("Created a new user.");
                            };
                        });
                    };
                });
            } else if (row) {
                //Compare stored password with provided password
                crypto.pbkdf2(req.body.pass, row.salt, 1000, 64, "sha512", (err, derivedKey) => {
                    if (err) {
                        res.send("Error hashing password: " + err);
                    } else {
                        const hashedPassword = derivedKey.toString("hex");

                        if (row.password === hashedPassword) {
                            req.session.user = req.body.user;
                            res.redirect("/convoList")
                        } else {
                            res.send("Incorrect Password.")
                        };
                    };
                });
            };
        });
    } else {
        res.send("Please enter both a username and password");
    };
});

//handle convoList
app.get("/convoList", isAuthenticated, (req, res) => {
    db.all("SELECT * FROM convos;", [], (err, rows) => {
        if (err) {
            console.error(err);
            res.status(500).send("Database error.");
        } else {
            //pass conversations to convoList.js       
            res.render("convoList", { convos: rows });
        }
    });
});

app.post("/convoList", isAuthenticated, (req, res) => {
    const convoTitle = req.body.convoTitle;
    if (!convoTitle) {
        return res.status(400).send("Conversation title is required.");
    };
    db.get("SELECT * FROM convos WHERE title=?;", [convoTitle], (err, row) => {
        if (err) {
            console.error(err);
            res.status(500).send("Database error.");
        } else if (row) {
            res.status(400).send("A conversation with this title already exists.");
        } else {
            db.run("INSERT INTO convos (title) VALUES (?);", [convoTitle], (err) => {
                if (err) {
                    console.error(err);
                    res.status(500).send("Error creating conversation.");
                } else {
                    res.redirect("/convoList");
                };
            });
        };
    });
});

app.get("/chat/:convo_id", isAuthenticated, (req, res) => {
    const convoID = req.params.convo_id;

    //SQL Query to fetch posts and user details from the conversation
    db.all("SELECT posts.poster, posts.content, posts.time, users.username FROM posts JOIN users ON posts.poster=users.uid WHERE convo_id=? ORDER BY time", [convoID], (err, rows) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Database error.");
        };

        //render the page, passing posts data
        res.render("chat", { convo_id: convoID, posts: rows });
    });
});

app.post("/chat/:convo_id", isAuthenticated, (req, res) => {
    const convoID = req.params.convo_id;

    //store the post in the database
    db.run("INSERT INTO posts (poster, content, time, convo_id) VALUES (?, ?, ?, ?)", [req.session.user, req.body.content, new Date(), convoID], (err) => {
        if (err) {
            console.error("Error saving post to database.");
            return;
        };

        db.all("SELECT * FROM posts WHERE convo_id=?", [convoID], (err, rows) => {
            if (err) {
                console.error(err);
                return res.status(500).send("Database error.");
            };
            
            //render the page, passing posts data
            res.render("chat", { convo_id: convoID, posts: rows });
            console.log(rows);

        });
    });
});

//handle userPage
app.get("/userPage/:poster", isAuthenticated, (req, res) => {
    const POSTER = req.params.poster

    //get user's posts from the database
    db.all("SELECT poster, content, time FROM posts WHERE poster=? ORDER BY time", [POSTER], (err, rows) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Database error.");
        };

        if (!POSTER) {
            return res.status(400).send("Invalid poster ID.");
        }

        if (!rows || rows.length === 0) {
            return res.status(204).send("No posts.");
        };

        //render the page, passing posts data
        res.render("userPage", { poster: POSTER, posts: rows });
    });
});