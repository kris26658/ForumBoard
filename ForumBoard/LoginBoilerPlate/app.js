//to install required modules, in terminal: "npm i sqlite3 express ejs"

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

const PORT = 3000 //set port number

function isAuthenticated(req, res, next) {
    if (req.session.user) next()
    else res.redirect("/login")
};

const db = new sqlite3.Database("data/database.db", (err) => {
    if (err) {
        console.log(err);
    } else {
        app.listen(PORT, () => {
            console.log("Server started on port", PORT)
        })
    };
});

app.get("/", (req, res) => {
    res.render("login");
});

app.post("/login", (req, res) => {
    if (req.body.user && req.body.email && req.body.pass) {
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
                        
                        db.run("INSERT INTO users (username, email, password, salt) VALUES (?, ?, ?, ?);", [req.body.user, req.body.email, hashedPassword, salt], (err) => {
                            if (err) {
                                res.send("Database error: \n" + err);
                            } else{
                                res.send("Created new user");
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
                            res.redirect("/home");
                        } else {
                            res.send("Incorrect Password.")
                        };
                    };
                });
            };
        });
    } else {
        res.send("Please enter a username, email, and password");
    };
});

app.get("/home", isAuthenticated, (req, res) => {
    try {
        res.render("home", { user: req.session.user })
    }
    catch (error) {
        res.send(error.message)
    }
});