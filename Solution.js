import express from "express";
import bodyParser from "body-parser";
import pg, { Client } from "pg";
import bcrypt, { hash } from "bcrypt";
import session from "express-session";
import env from "dotenv";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import { name } from "ejs";


const app = express();
const port = 3000;
const saltRound = 5;
env.config();

app.use(session({
    secret : process.env.SECRET,
    resave : false,
    saveUninitialized : true,
}));

app.use(bodyParser.urlencoded({extended : true}));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user : process.env.PG_USER,
    host : process.env.PG_HOST,
    database : process.env.PG_DATABASE,
    password : process.env.PG_PASSWORD,
    port : process.env.PG_PORT,
});

db.connect();

app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs",{message : req.query.message});
});

app.get("/customer", async(req, res) => {
   const id = req.user.id;
  try{
   await db.query("UPDATE users SET role= $1 WHERE id = $2",["Customer",id]);
   res.render("customer.ejs");
  }catch(err){
    console.log(err);
    res.send("Something wents wrong");
  }
});

app.get("/seller",async (req, res) => {
     const id = req.user.id;
  try{
   await db.query("UPDATE users SET role= $1 WHERE id = $2",["Seller",id]);
   res.render("seller.ejs");
  }catch(err){
    console.log(err);
    res.send("Something wents wrong");
  }
});

app.get("/aurenix", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("aurenix.ejs");
  } else {
    res.redirect("/login");
  }
});

// app.post("/login", passport.authenticate("local", {
//   successRedirect: "/secrets",
//   failureRedirect: "/login"
// }));

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user) => {
    if (err || !user) {
      return res.redirect("/login?message=Please enter valid email and password");
    }

    req.logIn(user, (err) => {
      if (err) {
        return res.redirect("/login?message=Login failed");
      }

      if (user.role === "Customer") {
        return res.redirect("/customer");
      } else if (user.role === "Seller") {
        return res.redirect("/seller");
      } else {
        return res.redirect("/aurenix");
      }
    });
  })(req, res, next);
});


app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect("/");
  });
});

//
app.get("/set-password", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  if (req.user.password) return res.redirect("/aurenix");

  res.render("setGooglePassword.ejs", { message: "" });
});

app.post("/set-password", async (req, res) => {
  const password = req.body.password;
  const userId = req.user.id;

  if (!password || password.length < 6) {
    return res.render("setGooglePassword.ejs", { message: "Password must be at least 6 characters." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, saltRound);
    await db.query("UPDATE users SET password = $1 WHERE id = $2", [hashedPassword, userId]);
    res.redirect("/aurenix");
  } catch (err) {
    console.log(err);
    res.render("setGooglePassword.ejs", { message: "Something went wrong." });
  }
});
//



app.get("/auth/google",
    passport.authenticate("google",{scope : ["profile", "email"]})
);

// app.get("/auth/google/aurenix",
//     passport.authenticate("google",{
//         successRedirect : "/aurenix",
//         failureRedirect : "/login"
//     })
// )
app.get("/auth/google/aurenix", passport.authenticate("google", { failureRedirect: "/login" }), (req, res) => {
  if (!req.user.password) {
    res.redirect("/set-password"); 
  } else {
    res.redirect("/aurenix");
  }
});


app.post("/register", async (req, res)=>{
   const email = req.body.username;
   const password = req.body.password;
   const name = req.body.name;
   try{
     const checkUser = await db.query("SELECT * FROM users WHERE email = $1",[email])

     if(checkUser.rows.length > 0){
        res.redirect("/login");
     }else{
        bcrypt.hash(password, saltRound, async(err, hash)=>{
           if(err){
            console.log("Error while hashing",err);
           }else{
            const result = await db.query("INSERT INTO users (email, password, name, created_at) VALUES ($1,$2, $3, CURRENT_TIMESTAMP) RETURNING * ",[email, hash, name]);
            const user = result.rows[0];
            req.login(user, (err)=>{
                console.log("success");
                res.redirect("/aurenix");//
            })
           }
        });
     }

   }catch(err){
    console.log(err);
   }
 
});

passport.use(
    "local",
    new Strategy(async function verify(username, password, cb) {
        
        try{
           const checkUser = await db.query("SELECT * FROM users WHERE email = $1",[username])

            if(checkUser.rows.length >0 ){
                const user = checkUser.rows[0];
                const storedHashedPassword = user.password;

                bcrypt.compare(password, storedHashedPassword, (err, valid)=>{
                    if(err){
                        console.error("Error while comparing password",err);
                    }else{
                        if(valid){
                           return cb (null, user);
                        }else{
                           return cb (null, false);
                        }
                    }
                })

            }else{
                return cb ("User not found");
            }

        }catch(err){
            console.log(err);
        }
    })
)

// passport.use(
//     "google",
//     new GoogleStrategy({
//        clientID : process.env.CLIENT_ID,
//        clientSecret : process.env.CLIENT_SECRET,
//        callbackURL : "http://localhost:3000/auth/google/aurenix",
//        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
//     },
//     async (accessToken, refreshToken, profile, cb) =>{
//         try{

//             const checkUser = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);

//             if(checkUser.rows.length === 0 ){
//               const newUser = await db.query("INSERT INTO users(email, password, name) VALUES ($1, $2, $3) RETURNING * ",[profile.email, "google", profile.displayName]);
//               return cb (null , newUser.rows[0]);
//             }else{
//                 return cb (null, checkUser.rows[0]);
//             }


//         }catch(err){console.log(err);}
//     }
// )
// )

passport.use(
    "google",
    new GoogleStrategy({
       clientID : process.env.CLIENT_ID,
       clientSecret : process.env.CLIENT_SECRET,
       callbackURL : "http://localhost:3000/auth/google/aurenix",
       userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) =>{
        try{

            const checkUser = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);

            if(checkUser.rows.length === 0 ){
              const newUser = await db.query("INSERT INTO users(email, name, created_at) VALUES ($1, $2, CURRENT_TIMESTAMP) RETURNING * ",[profile.email, profile.displayName]);
              return cb (null , newUser.rows[0]);
            }else{
                return cb (null, checkUser.rows[0]);
            }


        }catch(err){console.log(err);}
    }
)
)



passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    cb(null, result.rows[0]);
  } catch (err) {
    cb(err, null);
  }
});




app.listen(port, ()=>{
    console.log("Server is Running at" + port);
});



// app.post("/register",async(res, req) => {
//     const email = req.body.username;
//     const password = req.body.password;

//     try{
//         const checkUser = await db.query("SELECT FROM users WHERE email = $1",[email]);

//         if(checkUser.rows.length >0 ){
//             console.log("user Already exists")
//             res.redirect("/login");
//         }else{
//             bcrypt.hash(password, saltRound, async (err, hash) => {

//                 if(err){
//                     console.log(err);
//                 }else{
//                     const result = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",[email, hash]);
//                     const user = result.rows[0];
//                     req.login(user, (err)=>{
//                       res.redirect("/sectres")//
//                     })
//                 }
//             })
//         }
//     }catch(err){
//         console.log(err);
//     }
// })





// import express from "express";
// import bodyParser from "body-parser";
// import pg, { Client } from "pg";
// import bcrypt, { hash } from "bcrypt";
// import session from "express-session";
// import env from "dotenv";
// import passport from "passport";
// import { Strategy } from "passport-local";
// import GoogleStrategy from "passport-google-oauth2";


// const app = express();
// const port = 3000;
// const saltRound = 5;
// env.config();

// app.use(session({
//     secret : process.env.SECRET,
//     resave : false,
//     saveUninitialized : false,
// }));

// app.use(bodyParser.urlencoded({extended : true}));
// app.use(express.static("public"));

// app.use(passport.initialize());
// app.use(passport.session());



// const db = new pg.Client({
//     user : process.env.PG_USER,
//     host : process.env.PG_HOST,
//     database : process.env.PG_DATABASE,
//     password : process.env.PG_PASSWORD,
//     port : process.env.PG_PORT,
// });

// db.connect();

// app.get("/", (req, res) => {
//     res.render("home.ejs");
// });

// app.get("/login", (req, res) => {
//   res.render("login.ejs");
// });

// app.get("/fillInfo",(req, res) => {
//   res.render("info.ejs");
// });

// app.get("/register",(req, res) => {
//   res.render("register.ejs");
// });

// app.get("/aurenix", (req, res) => {
//   if (req.isAuthenticated()) {
//     // res.render("aurenix.ejs");
//     if(req.user.role === "Customer"){
//       res.render("customer.ejs");
//     }else if(req.user.role === "Seller"){
//       res.render("seller.ejs");
//     }else{
//       res.redirect("/fillInfo");
//     }
//   } else {
//     res.redirect("/login");
//   }
// });

// app.post("/login", passport.authenticate("local", {
//   successRedirect: "/fillInfo",
//   failureRedirect: "/login",
// }));

// app.get("/logout", (req, res) => {
//   req.logout((err) => {
//     if (err) console.log(err);
//     res.redirect("/");
//   });
// });


// app.get("/auth/google",
//     passport.authenticate("google",{scope : ["profile", "email"]})
// );

// app.get("/auth/google/aurenix",
//     passport.authenticate("google",{
//         successRedirect : "/fillInfo",
//         failureRedirect : "/login"
//     }),
//     (req, res)=>{
//       if(!req.user.role){
//         res.redirect("/fillInfo");
//       }else if(req.user.role === "Customer"){
//           res.render("customer.ejs");
//       }else{
//           res.render("seller.ejs");
//       }
//     }
// )

// //
// function ensureAuthenticated(req, res, next) {
//   if (req.isAuthenticated()) {
//     return next();
//   }
//   // res.redirect("/login");
//   if(req.user.role === "Customer"){
//           res.render("customer.ejs");
//       }else if(req.user.role === "Seller"){
//           res.render("seller.ejs");
//       }else{
//         res.render("info.ejs", { message: "Please select your role." });
//       }
// }


// app.post("/setInfo", ensureAuthenticated, async (req, res)=> {
//   console.log("req.user:", req.user);

//   const userId = req.user.id; 
//   const role = req.body.role;
//   const name = req.body.name;
//   const created_at = new Date();

//    try{
//        await db.query("UPDATE users SET role = $1, name = $2, created_at =$3 WHERE id = $4",[role, name, created_at, userId]);

//        req.user.role = role;
//       //  res.redirect("/aurenix");//
//        if(req.user.role === "Customer"){
//           res.render("customer.ejs");
//       }else if(req.user.role === "Seller"){
//           res.render("seller.ejs");
//       }else{
//         res.render("info.ejs", { message: "Please select your role." });
//       }
//    }catch(err){
//     console.log(err);
//    }
// });

// app.post("/register", async (req, res)=>{
//    const email = req.body.username;
//    const password = req.body.password;
   
//    try{
//      const checkUser = await db.query("SELECT * FROM users WHERE email = $1",[email])

//      if(checkUser.rows.length > 0){
//         res.redirect("/login");
//      }else{
//         bcrypt.hash(password, saltRound, async(err, hash)=>{
//            if(err){
//             console.log("Error while hashing",err);
//            }else{
//             const result = await db.query("INSERT INTO users (email, password) VALUES ($1,$2) RETURNING * ",[email, hash]);
//             const user = result.rows[0];
//             req.login(user, (err)=>{
//                 console.log("success");
//                 // res.redirect("/aurenix");//
//                 res.redirect("/fillInfo")
//             })
//            }
//         });
//      }

//    }catch(err){
//     console.log(err);
//    }
// });

// passport.use(
//     "local",
//     new Strategy(async function verify(username, password, cb) {
        
//         try{
//            const checkUser = await db.query("SELECT * FROM users WHERE email = $1",[username]);

//             if(checkUser.rows.length >0 ){
//                 const user = checkUser.rows[0];
//                 const storedHashedPassword = user.password;
//                 bcrypt.compare(password, storedHashedPassword, (err, valid)=>{
//                     if(err){
//                         console.error("Error while comparing password",err);
//                     }else{
//                         if(valid){
//                            return cb (null, user);
//                         }else{
//                            return cb (null, false);
//                         }
//                     }
//                 })
//             }else{
//                 return cb(null, false);
//             }
//         }catch(err){
//             console.log(err);
//         }
//     })
// )

// passport.use(
//     "google",
//     new GoogleStrategy({
//        clientID : process.env.CLIENT_ID,
//        clientSecret : process.env.CLIENT_SECRET,
//        callbackURL : "http://localhost:3000/auth/google/aurenix",
//        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
//     },
//     async (accessToken, refreshToken, profile, cb) =>{
//         try{
//             const checkUser = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);

//             if(checkUser.rows.length === 0 ){
//               const newUser = await db.query("INSERT INTO users(email, password) VALUES ($1, $2)",[profile.email, "google"]);
//               return cb (null , newUser.rows[0]);
//             }else{
//                 return cb (null, checkUser.rows[0]);
//             }


//         }catch(err){console.log(err);}
//     }
// )
// )

// // passport.serializeUser((user, cb) => {
// //   cb(null, user);
// // });

// // passport.deserializeUser((user, cb) => {
// //   cb(null, user);
// // })
// passport.serializeUser((user, done) => {
//   done(null, user.id); // only store ID in session
// });

// passport.deserializeUser(async (id, done) => {
//   try {
//     const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
//     if (result.rows.length > 0) {
//       done(null, result.rows[0]); // this becomes req.user
//     } else {
//       done(null, false);
//     }
//   } catch (err) {
//     done(err, null);
//   }
// });



// app.listen(port, ()=>{
//     console.log("Server is Running at" + port);
// });







// app.post("/register",async(res, req) => {
//     const email = req.body.username;
//     const password = req.body.password;

//     try{
//         const checkUser = await db.query("SELECT FROM users WHERE email = $1",[email]);

//         if(checkUser.rows.length >0 ){
//             console.log("user Already exists")
//             res.redirect("/login");
//         }else{
//             bcrypt.hash(password, saltRound, async (err, hash) => {

//                 if(err){
//                     console.log(err);
//                 }else{
//                     const result = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",[email, hash]);
//                     const user = result.rows[0];
//                     req.login(user, (err)=>{
//                       res.redirect("/sectres")//
//                     })
//                 }
//             })
//         }
//     }catch(err){
//         console.log(err);
//     }
// })



// sample 
// import express from "express";
// import bodyParser from "body-parser";
// import pg, { Client } from "pg";
// import bcrypt, { hash } from "bcrypt";
// import session from "express-session";
// import env from "dotenv";
// import passport from "passport";
// import { Strategy } from "passport-local";
// import GoogleStrategy from "passport-google-oauth2";


// const app = express();
// const port = 3000;
// const saltRound = 5;
// env.config();

// app.use(session({
//     secret : process.env.SECRET,
//     resave : false,
//     saveUninitialized : true,
// }));

// app.use(bodyParser.urlencoded({extended : true}));
// app.use(express.static("public"));

// app.use(passport.initialize());
// app.use(passport.session());

// const db = new pg.Client({
//     user : process.env.PG_USER,
//     host : process.env.PG_HOST,
//     database : process.env.PG_DATABASE,
//     password : process.env.PG_PASSWORD,
//     port : process.env.PG_PORT,
// });

// db.connect();

// app.get("/", (req, res) => {
//     res.render("home.ejs");
// });

// app.get("/login", (req, res) => {
//   res.render("login.ejs");
// });

// app.get("/aurenix", (req, res) => {
//   if (req.isAuthenticated()) {
//     res.render("aurenix.ejs");
//   } else {
//     res.redirect("/login");
//   }
// });

// app.post("/login", passport.authenticate("local", {
//   successRedirect: "/secrets",
//   failureRedirect: "/login"
// }));

// app.get("/logout", (req, res) => {
//   req.logout((err) => {
//     if (err) console.log(err);
//     res.redirect("/");
//   });
// });



// app.get("/auth/google",
//     passport.authenticate("google",{scope : ["profile", "email"]})
// );

// app.get("/auth/google/aurenix",
//     passport.authenticate("google",{
//         successRedirect : "/aurenix",
//         failureRedirect : "/login"
//     })
// )


// app.post("/register", async (req, res)=>{
//    const email = req.body.username;
//    const password = req.body.password;
   
//    try{
//      const checkUser = await db.query("SELECT * FROM users WHERE email = $1",[email])

//      if(checkUser.rows.length > 0){
//         res.redirect("/login");
//      }else{
//         bcrypt.hash(password, saltRound, async(err, hash)=>{
//            if(err){
//             console.log("Error while hashing",err);
//            }else{
//             const result = await db.query("INSERT INTO users (email, password) VALUES ($1,$2) RETURNING * ",[email, hash]);
//             const user = result.rows[0];
//             req.login(user, (err)=>{
//                 console.log("success");
//                 res.redirect("/secrets");//
//             })
//            }
//         });
//      }

//    }catch(err){
//     console.log(err);
//    }
 
// });

// passport.use(
//     "local",
//     new Strategy(async function verify(username, password, cb) {
        
//         try{
//            const checkUser = await db.query("SELECT * FROM users WHERE email = $1",[username])

//             if(checkUser.rows.length >0 ){
//                 const user = checkUser.rows[0];
//                 const storedHashedPassword = user.password;

//                 bcrypt.compare(password, storedHashedPassword, (err, valid)=>{
//                     if(err){
//                         console.error("Error while comparing password",err);
//                     }else{
//                         if(valid){
//                            return cb (null, user);
//                         }else{
//                            return cb (null, false);
//                         }
//                     }
//                 })

//             }else{
//                 return cb ("User not found");
//             }

//         }catch(err){
//             console.log(err);
//         }
//     })
// )

// passport.use(
//     "google",
//     new GoogleStrategy({
//        clientID : process.env.CLIENT_ID,
//        clientSecret : process.env.CLIENT_SECRET,
//        callbackURL : "http://localhost:3000/auth/google/aurenix",
//        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
//     },
//     async (accessToken, refreshToken, profile, cb) =>{
//         try{

//             const checkUser = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);

//             if(checkUser.rows.length === 0 ){
//               const newUser = await db.query("INSERT INTO users(email, password) VALUES ($1, $2)",[profile.email, "google"]);
//               return cb (null , newUser.rows[0]);
//             }else{
//                 return cb (null, checkUser.rows[0]);
//             }


//         }catch(err){console.log(err);}
//     }
// )
// )

// passport.serializeUser((user, cb) => {
//   cb(null, user);
// });

// passport.deserializeUser((user, cb) => {
//   cb(null, user);
// })



// app.listen(port, ()=>{
//     console.log("Server is Running at" + port);
// });



// // app.post("/register",async(res, req) => {
// //     const email = req.body.username;
// //     const password = req.body.password;

// //     try{
// //         const checkUser = await db.query("SELECT FROM users WHERE email = $1",[email]);

// //         if(checkUser.rows.length >0 ){
// //             console.log("user Already exists")
// //             res.redirect("/login");
// //         }else{
// //             bcrypt.hash(password, saltRound, async (err, hash) => {

// //                 if(err){
// //                     console.log(err);
// //                 }else{
// //                     const result = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",[email, hash]);
// //                     const user = result.rows[0];
// //                     req.login(user, (err)=>{
// //                       res.redirect("/sectres")//
// //                     })
// //                 }
// //             })
// //         }
// //     }catch(err){
// //         console.log(err);
// //     }
// // })