const express = require('express');
const bodyParser = require('body-parser');
const router = express.Router();
//const app = express();

const db = require('./dbconnect').db; //database
const ps = require('./dbconnect').ps; //prepared sql statements

const jwt = require("jsonwebtoken");
const bcrypt = require('bcryptjs');

const secret = "rusten_felge"; //used to create the token



router.post("/login/", async function (req, res) {
   
    let login = req.body;
    
    let sql = `PREPARE get_user (text) AS
                    SELECT * FROM users WHERE loginname=$1;
                    EXECUTE get_user('${login.username}')`;


    try {
        let datarows = await db.any(sql);
        db.any("DEALLOCATE get_user");


        let user = await datarows.find(user => {
            return login.username === user.loginname;
        });
        let passwordMatch = await bcrypt.compareSync(login.password, user.password);
        
        
        if (user && passwordMatch) {
            //we have a valid user -> create the token        
            let payload = await {
                username: datarows.loginname,
                fullname: datarows.fullname
            };
            let tok = await jwt.sign(payload, secret, {
                expiresIn: "12h"
            });
            //send logininfo + token to the client
            res.status(200).json({
                username: user.loginname,
                fullname: user.fullname,
                token: tok
            });
        } else {
            res.status(400).send("feil brukernavn eller passord");
        }

    } catch (err) {
        res.status(500).json({
            error: err
        }); //something went wrong!
    }


});




router.post("/register/", async function (req, res) {
    
    let register = req.body;
    let encrPassw = bcrypt.hashSync(register.password, 10); //hash the password    


    var sql = `PREPARE insert_user (int, text, text, text) AS
                INSERT INTO users VALUES(DEFAULT, $2, $3, $4); EXECUTE insert_user
                (0, '${register.username}', '${encrPassw}', '${register.fullname}')`;    



    try {
        let datarows = await db.any(sql);
        db.any("DEALLOCATE insert_user");
        
        let payload = {username: register.username, fullname: register.fullname};
        let tok = jwt.sign(payload, secret, {expiresIn: "12h"});

        //send logininfo + token to the client
        res.status(200).json({username: register.username, fullname: register.fullname, token: tok}); 
        

    } catch (err) {
        res.status(500).json({
            error: err
        }); //something went wrong!
    }


});


//export module -------------------------------------
module.exports = router;



