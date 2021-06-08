const express = require('express');
const mongo = require('mongodb').MongoClient;
const mongoose = require('mongoose');
const morgan = require('morgan'); //log reqs
const bodyParser = require('body-parser');
const app = express();
require('dotenv').config();
const session = require('express-session');
const flash = require('connect-flash');


/* Prevent CORS issues */
var cors = (function(req,res,next){
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', '*');
    next();
});
app.use(cors)




app.use(morgan('dev'));
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(flash())

app.use(function(req,res,next){
    res.setTimeout(480000, function(){
        console.log('Request has timed out');
        res.sendStatus(408);
    });
    next();
});

app.use(session({secret:process.env.SESSION_SECRET,resave:true,saveUninitialized:true}));

var routes = require('./app/routes/routes.js')(app);


app.engine('html', require('ejs').renderFile);
app.set('views', 'views');
app.set('view engine', 'html');

const port = process.env.PORT || 8080

app.listen(port,function(){
    console.log('Listening on ' + port)
})
