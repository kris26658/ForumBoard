//to install required modules, in terminal: "npm i http ws express ejs sqlite3 crypto jsonwebtoken express-session"

const express = require("express"); //import express
const ejs = require("ejs"); //import ejs
const sqlite3 = require("sqlite3"); //import sqlite3
const crypto = require("crypto"); //import crypto
const jwt = require('jsonwebtoken'); //import jsonwebtoken
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
    else res.redirect("/login")
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
    app.clients.forEach(client => {
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
    client.on("close", () => console.log(`${client.user} has disconnected.`)); //user disconnects
    broadcast(wss, userList(wss)); //reload user list

    client.on("message", (data) => {
        const parsedMsg = JSON.parse(data); //parse incoming message

        if (parsedMsg.user) {
            client.user = parsedMsg.user;
            broadcast(wss, userList(wss));
        };
        if (parsedMsg.text) {
            broadcast(wss, { user: client.user, text: parsedMsg.text });
        };
    });
}));

wss.message = (event) => {
    try {
        const message = JSON.parse(event.data);

        if (message.list) {
            const users = document.getElementById("users");
            users.innerHTML = ""; // Clear before updating
            message.list.forEach(user => {
                const li = document.createElement('li');
                li.textContent = user;
                users.appendChild(li);
            });
        }

        if (message.text) {
            const messages = document.getElementById("sentMessages");
            const p = document.createElement("p");
            p.textContent = `${message.user}: ${message.text}`;
            messages.appendChild(p);
            messages.scrollTop = messages.scrollHeight; //scroll to latest message
        }
    } catch (error) {
        console.error("Error parsing message:", error);
    }
};

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
    }

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

//handle chat
app.get("/chat", isAuthenticated, (req, res) => {
    const convoTitle = req.query.title;

    db.get("SELECT * FROM convos WHERE title = ?;", [convoTitle], (err, row) => {
        if (err) {
            console.error(err);
            res.status(500).send("Database error.");
        } else if (!row) {
            res.status(404).send("Conversation not found.");
        } else {
            res.render("chat", { user: req.session.user, convo: row });
        }
    });
});

app.get("/chat/:convo_id", isAuthenticated, (req, res) => {
    const user = req.user; // assuming user is stored in session or another method
    const convo_id = req.params.convo_id;
    
    db.get("SELECT * FROM posts JOIN convo ON posts.convo_id =? JOIN convo.uid WHERE convo.uid = ?;")[poster, content], (err, row) => {
        if (err) {
            console.error(err);
            res.status(500).send("Database error.");
        } else if (!row) {
            res.status(404).send("Conversation not found.");
        } else {
            res.render("chat", { posts: poster, content });
        };
    };

    db.all("SELECT * FROM posts;", [], (err, rows) => {
        if (err) {
            console.error(err);
            res.status(500).send("Database error.");
        } else {
            //pass conversations to convoList.js
            res.render("chat", { posts: rows });
        }
    });
});