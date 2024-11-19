//to install required modules, in terminal: "npm i sqlite3 express ejs crypto jsonwebtoken express-session ws http"

const sqlite3 = require("sqlite3"); //import sqlite3
const express = require("express"); //import express
const ejs = require("ejs"); //import ejs
const crypto = require("crypto"); //import crypto
const jwt = require('jsonwebtoken'); //import jsonwebtoken
const session = require('express-session'); //import express-session

const app = express(); //initialize express with app

app.set("view engine", "ejs"); // set view engine
app.use(express.urlencoded({ extended: true })); //encode url

app.use(session({
    secret: "Secret hehe",
    resave: false,
    saveUninitialized: false
}));

/*--------------
WebSocket Server
--------------*/

const PORT = 3000 //set port number

const WebSocket = require("ws"); //import WebSocket
const wss = new WebSocket.Server({ server: app }); //create new WebSocket server, attach it to http server

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
    else res.redirect("/login")
};

function broadcast(wss, data) {
    const message = JSON.stringify(data);
    wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(message);
        };
    });
};

function userList(wss) {
    let users = [];
    wss.clients.forEach(client => {
        if (client.name) {
            users.push(client.name);
        };
    });
    return { list: users };
};

wss.on("connection", (ws => { //on connection to WebSocket server
    ws.on("close", () => console.log(`${ws.name} has disconnected.`)); //user disconnects
    broadcast(wss, userList(wss)); //reload user list

    ws.on("message", (data) => {
        const parsedMsg = JSON.parse(data); //parse incoming message

        if (parsedMsg.name) {
            ws.name = parsedMsg.name;
            broadcast(wss, userList(wss));
        };
        if (parsedMsg.text) {
            broadcast(wss, { user: ws.name, text: parsedMsg.text });
        };
    });
}));

/*---------------
GET/POST Requests
---------------*/

//handle index
app.get("/", (req, res) => {
    res.render("index");
});

//handle login
app.post("/", (req, res) => {
    if (req.body.user && req.body.pass) {
        db.get("SELECT * FROM users WHERE username = ?", [user], function (err, row) {
            if (err) {
                res.render("error", {error: "Error checking for existing users."});
                return;
            };
            if (row) {
                res.render("error", {error: "Username or email is already in use." });
                return;
            };
        });
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

                                res.redirect("/index");
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

//handle chat
app.get("/chat", isAuthenticated, (req, res) => {
    const name = req.body.user;
    if (!name) {
        return res.redirect("/");
    };
    res.render("chat", { user: req.session.user })
});