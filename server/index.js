const express = require ("express");
const bodyParser = require("body-parser");
const app = express();
const mysql = require("mysql");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const session =require("express-session");

const bcrypt = require("bcrypt");
const saltRounds=10;

const jwt = require("jsonwebtoken");

app.use(express.json());
app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true
}));
app.use(cookieParser());
app.use(bodyParser.urlencoded({extended:true}));
app.use(session({
    key: "userId",
    secret: "subscribe",
    resave: false,
    saveUninitialized: false,
    cookie : {
        expires: 60 * 60 * 24,
    },
})
);

const db = mysql.createConnection({
    host:"127.0.0.1",
    port: '3307',
    user:"root",
    password:"root",
    database:"auth_register",
});


app.get("/", (req, res)=>{
    res.send("Hello Naz!");
})

app.post("/register", (req, res)=>{
     const username=req.body.username;
     const password=req.body.password;

     bcrypt.hash(password, saltRounds, (err, hash) =>{
        if (err){
            console.log(err);
        }
          db.query("INSERT INTO users (username, password) values (?, ?)",
         [username, hash],
         (err, result)=>{
        console.log(err);
     });
     })
});

const verifyJWT = (req, res, next) => {
const token= req.headers["x-access-token"];
if(!token){
    res.send("yo, we need a token,please give it to us next time!");
}else{
    jwt.verify(token, "jwtSecret", (err, decoded)=>{
    if(err){
        res.json({auth: false , message: "U failed to authenticate"});
    }else{
     req.userId = decoded.id;
     next();
    }
    });
}
};

app.get("/isUserAuth", verifyJWT , (req, res)=>{
// res.send("You are authenticated.Congrats!");
 res.json({ message: "You are authenticated.Congrats!"});
});

app.get("/login", (req, res)=>{
    if(req.session.user){
        res.send({loggedIn:true, user: req.session.user});
    }else{
       res.send({loggedIn:false});
    }
});

app.post("/login", (req, res)=>{
     const username=req.body.username;
     const password=req.body.password;

    db.query("SELECT * FROM users WHERE username=?;",
     username,
    (err, result)=>{
        if (err){
            res.send({err:err});
        }

        if (result.length > 0){
            bcrypt.compare(password, result[0].password, (error, response)=>{
                if(response){
                    const id = result[0].id;
                    const token = jwt.sign({id}, "jwtSecret", {
                        expiresIn: 300,
                    });
                     req.session.user = result;
                      res.json({auth:true, token:token, result: result});
                }else{
                    res.json({auth:false, message: "wrong username/password combination"});
                }
            })

        } else {
           res.json({auth:false, message: "no user exist"});
        }


    });

});

app.listen(3001, () =>{
    console.log("Server is running on port 3001!");
})