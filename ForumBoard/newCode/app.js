//to install required modules, in terminal: "npm i sqlite3 express ejs crypto jsonwebtoken express-session"

const sqlite3 = require("sqlite3"); //import sqlite3
const express = require("express"); //import express
const ejs = require("ejs"); //import ejs
const crypto = require("crypto"); //import crypto
const jwt = require('jsonwebtoken'); //import jsonwebtoken
const session = require('express-session'); //import express-session

const app = express(); //initialize express with app

app.set("view engine", "ejs"); // set view engine
app.use(express.urlencoded({ extended: true })); //encode url

//allows calling of files in public folder
app.use(express.static('public'))

app.use(session({
    secret: "Secret hehe",
    resave: false,
    saveUninitialized: false
}));

const PORT = 3000 //set port number

const db = new sqlite3.Database("data/database.db", (err) => {
    if (err) {
        console.log(err);
    } else {
        app.listen(PORT, () => {
            console.log("Server started on port", PORT)
        })
    };
});



function isAuthenticated(req, res, next) {
    if (req.session.user) next()
    else res.redirect("/")
};

function userList(app) {
    let users = [];
    app.clients.forEach(client => {
        if (client.user) {
            users.push(client.user);
        };
    });
    return { list: users };
};

app.on("connection", (app => { //on connection to server
    app.on("close", () => console.log(`${app.user} has disconnected.`)); //user disconnects
    broadcast(app, userList(app)); //reload user list

    app.on("message", (data) => {
        const parsedMsg = JSON.parse(data); //parse incoming message

        if (parsedMsg.user) {
            app.user = parsedMsg.user;
            broadcast(app, userList(app));
        };
        if (parsedMsg.text) {
            broadcast(app, { user: app.user, text: parsedMsg.text });
        };
    });
}));

app.message = (event) => {
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
                            res.redirect("/chat"); 
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

//posts table

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
    db.all("SELECT * FROM posts WHERE poster = ?", [req.session.user], (err, rows) => {
        if (err) {
            console.log(err);
            res.send("There was an error fetching messages:\n" + err);
        } else {
            res.render("chat", { user: req.session.user, messages: rows });
        }
    });
});
