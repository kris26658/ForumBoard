//to install required modules, in terminal: "npm i express ejs ws http"

const express = require("express"); //import express
const app = express(); //initialize express with app

const ejs = require("ejs"); //import ejs

app.set("view engine", "ejs"); // set view engine
app.use(express.urlencoded({ extended: true })); //encode url

/*---------
HTTP Server
---------*/

const http = require('http').Server(app); //import http, create http server and associate it with express

const PORT = process.env.PORT || 1000; //change port number from default
http.listen(PORT, console.log(`Server started on port ${PORT}`)); //start http server, listen on given port

/*--------------
WebSocket Server
--------------*/

const WebSocket = require("ws"); //import WebSocket
const wss = new WebSocket.Server({ server: http }); //create new WebSocket server, attach it to http server

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

//handle chat
app.get("/chat", (req, res) => {
    const name = req.query.name;
    if (!name) {
        return res.redirect("/");
    };
    res.render("chat", { name });
});