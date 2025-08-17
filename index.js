import express from "express";
import bodyParser from "body-parser";
import pg, { Client } from "pg";
import bcrypt, { hash } from "bcrypt";
import session from "express-session";
import env from "dotenv";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import multer from "multer";

const app = express();
const port = 3000;
const saltRound = 5;
env.config();

const storage = multer.diskStorage({
  destination : function (req, file, cb){
    cb(null, "public/image");
  },
  filename : function (req, file, cb){
    cb(null, Date.now()+file.originalname);
  }
})

const upload = multer({storage : storage});

app.use(session({
    secret : process.env.SECRET,
    resave : false,
    saveUninitialized : true,
}));

app.use(bodyParser.urlencoded({extended : true}));
app.use(express.static("public"));
app.use(express.json());


app.use(passport.initialize());
app.use(passport.session());
app.set("view engine", "ejs");

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

app.get("/auth/google",
    passport.authenticate("google",{scope : ["profile", "email"]})
);

app.get("/auth/google/aurenix", passport.authenticate("google", { failureRedirect: "/login" }), (req, res) => {
  if (!req.user.password) {
    res.redirect("/set-password"); 
  } else {
    res.redirect("/aurenix");
  }
});

app.get("/set-password", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  if (req.user.password) return res.redirect("/aurenix");

  res.render("setGooglePassword.ejs", { message: "" });
});


app.get("/login", (req, res) => {
  res.render("login.ejs",{message : req.query.message});
});

app.get("/aurenix", async (req, res) => {
  if (!req.isAuthenticated()) {
   return res.redirect("/login");
  } 
  
  try{
    const id = req.user.id;
     const result = await db.query("SELECT * FROM users WHERE id = $1",[id]);
      const role = result.rows[0].role;

          if(role === "Customer"){
            res.redirect("customer");
          }else if(role === "Seller"){
            res.redirect("/Seller");
          }else{
            res.render("aurenix.ejs");
          }
       
  }catch (err) {
    console.log(err);
    res.send("Something went wrong.");
  }
});

app.get("/customer", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");

  const id = req.user.id;

  try {
    const userResult = await db.query("SELECT role FROM users WHERE id = $1", [id]);
    const currentRole = userResult.rows[0].role;

    if (currentRole !== "Customer") {
      await db.query("UPDATE users SET role = $1 WHERE id = $2", ["Customer", id]);
      req.user.role = "Customer"; 
    }

    const result = await db.query("SELECT * FROM product_table");
    res.render("customer.ejs", { product: result.rows });

  } catch (err) {
    console.log(err);
    res.send("Something went wrong");
  }
});


app.get("/seller", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");

  const id = req.user.id;

  try {
    const userResult = await db.query("SELECT role FROM users WHERE id = $1", [id]);
    const currentRole = userResult.rows[0].role;

    if (currentRole !== "Seller") {
      await db.query("UPDATE users SET role = $1 WHERE id = $2", ["Seller", id]);
      req.user.role = "Seller"; 
    }

    const result = await db.query("SELECT * FROM product_table WHERE seller_id = $1", [id]);
    res.render("seller.ejs", { product: result.rows });

  } catch (err) {
    console.log(err);
    res.send("Something went wrong");
  }
});


app.get("/addProduct",(req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  res.render("addProduct.ejs");
});

app.get("/editProduct/:id", async (req,res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  const productID = req.params.id;
  const userID = req.user.id;
  
  try{
    const result = await db.query("SELECT * FROM product_table WHERE seller_id = $1 AND id = $2",[userID, productID]);
    const product = result.rows[0];
    res.render("editProduct.ejs",{product : product});

  }catch(err){
    res.send(err);
  }

});

app.get("/orderConfirmation",async (req, res)=>{
  res.render("orderConfirm");
});

app.get("/order/:id", async (req, res) =>{

  const id = req.params.id;
try{
  const select = await db.query("SELECT * FROM orders INNER JOIN product_table ON orders.product_id = product_table.id WHERE orders.id = $1",
    [id]
  );

  const order = select.rows[0]; 
  res.render("order.ejs",{order : order});
}catch(err){
  res.send(err);
}
});

app.get("/cart", async (req, res) => {
    if (!req.isAuthenticated()) return res.redirect("/login");

    const userId = req.user.id; 

    try {
        const result = await db.query(
        `SELECT cart.id AS cart_id, product_table.*
         FROM cart 
         INNER JOIN product_table ON cart.product_id = product_table.id
         WHERE cart.user_id = $1`,
            [userId]
        );

        const cartItems = result.rows;

        res.render("cart.ejs", { cartItems: cartItems });
    } catch (err) {
        console.error(err);
        res.send("Error fetching cart data");
    }
});

app.get("/cart/:id", async (req, res) =>{

  const id = req.params.id;
try{
  const select = await db.query("SELECT cart.id AS cart_id, cart.product_id, product_table.* FROM cart INNER JOIN product_table ON cart.product_id = product_table.id WHERE cart.id = $1",
    [id]
  );

  const order = select.rows[0]; 
  res.render("cartOrder.ejs",{order : order});
}catch(err){
  res.send(err);
}
});

app.get("/cartDelete/:id", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");

  const cartId = req.params.id;

  try {
    await db.query("DELETE FROM cart WHERE id = $1", [cartId]);
    res.redirect("/cart");
  } catch (err) {
    console.error("Error deleting cart item:", err);
    res.status(500).send("Error deleting cart item");
  }
});


app.get("/search", async (req, res) => {
  const search = req.query.search;

  try{
    const result = await db.query("SELECT * FROM product_table WHERE name ILIKE $1",[`%${search}%`]);
    const product = result.rows;
    res.render("search.ejs",{ product : product, search : search });
  }catch(err){
    res.send(err);
  }
});

app.get("/seeAllOrderSeller", async(req, res)=>{
   if (!req.isAuthenticated()) return res.redirect("/login");
   const userId = req.user.id; 
   try{
  const result = await db.query(`SELECT 
    product_table.name AS product_name,
    product_table.price AS product_price,
    product_table.image AS product_image,
    orders.total_price AS total_price,
    orders.quantity AS quantity,
    orders.status AS status,
    addresses.address AS address,
    addresses.pincode AS pincode,
    addresses.phone As phone,
    users.name AS buyer_name,
    users.email AS buyer_email
    FROM product_table 
    INNER JOIN orders ON orders.product_id = product_table.id
    INNER JOIN users ON users.id = orders.user_id
    INNER JOIN addresses ON addresses.user_id = orders.user_id
    WHERE product_table.seller_id = $1 `,[userId]);

    const cartResult = await db.query(`SELECT
      product_table.name AS product_name,
      product_table.price AS product_price,
      product_table.image AS product_image,
      cart_order.total_price AS total_price,
      cart_order.quantity AS quantity,
      cart_order.order_status AS order_status,
      cart_order.address AS address,
      cart_order.pincode AS pincode,
      cart_order.phone As phone,
      users.name AS buyer_name,
      users.email AS buyer_email
      FROM product_table
      INNER JOIN cart_order ON cart_order.product_id = product_table.id
      INNER JOIN users ON users.id = cart_order.user_id 
      WHERE product_table.seller_id = $1  
      `,[userId])

    const order = result.rows;
    const cartOrder = cartResult.rows;
    res.render("seeAllOrderSeller.ejs",{order,cartOrder});
   }catch(err){
    res.send(err);
   }
});


app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect("/");
  });
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


app.post("/addProduct", upload.array("image", 5) ,async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");

  const id = req.user.id; 
  const name = req.body.name;
  const discription = req.body.discription;
  const price = req.body.price;
  const image = req.files.map(file => file.filename);
  const stringImageName = JSON.stringify(image);

  try{
   await db.query("INSERT INTO product_table( seller_id,name, discription, price, stock, image, created_at) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)",
      [id, name, discription, price, "inStock", stringImageName]
    );
    res.redirect("/seller");
  }catch(err){
    res.send(err);
  }
  console.log(req.user.id);
});

app.post("/stock/:id", async (req, res) => {
  const id = req.params.id;
  const stock = req.body.stock;

  try{
    await db.query("UPDATE product_table SET stock = $1 WHERE id = $2 ",[stock, id]);

    res.redirect("/seller");
    
  }catch(err){
    res.send(err);
  }
});

app.post("/order/:id", async (req, res)=>{
  if (!req.isAuthenticated()) return res.redirect("/login");

  const user_id = req.user.id;
  const product_id = req.params.id;
  const price = req.body.price;
  
  try{

    const result = await db.query("INSERT INTO orders(user_id, product_id, price_each, order_date) VALUES($1, $2, $3, CURRENT_TIMESTAMP) RETURNING id",
      [user_id, product_id, price]
    );
     const id = result.rows[0].id;
    res.redirect("/order/"+id);
  }catch(err){
    res.send(err);
  }

});

app.post("/finalOrder/:id", async (req, res)=>{
  if (!req.isAuthenticated()) return res.redirect("/login");
  const id = req.user.id;
  const productId = req.params.id;
  const quantity = req.body.quantity;
  const totalPrice = req.body.total_price;
  const address = req.body.address;
  const pincode = req.body.pincode;
  const phone = req.body.phone;

  try{
    await db.query( "UPDATE orders SET quantity = $1, total_price = $2, status = $3 WHERE product_id = $4 AND user_id = $5",[quantity, totalPrice, "Ordered", productId, id]);

    await db.query("INSERT INTO addresses(user_id, address, pincode, phone, product_id) VALUES($1, $2, $3, $4, $5)",[id, address, pincode, phone, productId]);

    res.redirect("/orderConfirmation");
  }catch(err){
    res.send(err);
  }
});

app.post("/cart/:id", async(req, res)=>{
  const userId = req.user.id;
  const productId = req.params.id;
  
  try{
    await db.query("INSERT INTO cart(user_id, product_id, created_at) VALUES($1, $2,CURRENT_TIMESTAMP)",[userId, productId]);
    // res.redirect("/customer");
    res.json({ success: true });
  }catch(err){
    res.send(err);
  }
});

app.post("/cartOrder/:id", async (req, res)=>{
  if (!req.isAuthenticated()) return res.redirect("/login");
  const id = req.user.id;
  const productId = req.params.id;
  const quantity = req.body.quantity;
  const totalPrice = req.body.total_price;
  const address = req.body.address;
  const pincode = req.body.pincode;
  const phone = req.body.phone;
  const cartId = req.body.cart_id;

  try{

    await db.query("INSERT INTO cart_order(user_id,cart_id ,product_id, quantity, total_price, address, pincode, phone, order_status,created_at) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)",
      [id,cartId, productId, quantity, totalPrice, address, pincode, phone,"Ordered" ]);

    res.redirect("/orderConfirmation");
  }catch(err){
    res.send(err);
  }
});

app.post("/editProduct/:id", upload.single("image"), async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");

  const productID = req.params.id;
  const userID = req.user.id;
  const { name, discription, price } = req.body;
  let imageFilename = req.file ? req.file.filename : null;
  try {
    
    if (imageFilename) {
      // update with new image
      const stringImageName = JSON.stringify([imageFilename]);
      await db.query(
        "UPDATE product_table SET name=$1, discription=$2, price=$3, image=$4 WHERE id=$5 AND seller_id=$6",
        [name, discription, price, stringImageName, productID, userID]
      );
    } else {
      // keep old image
      await db.query(
        "UPDATE product_table SET name=$1, discription=$2, price=$3 WHERE id=$4 AND seller_id=$5",
        [name, discription, price, productID, userID]
      );
    }

    res.redirect("/seller");
  } catch (err) {
    res.send(err);
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


passport.use(
    "google",
    new GoogleStrategy({
       clientID : process.env.CLIENT_ID,
       clientSecret : process.env.CLIENT_SECRET,
       callbackURL : "https://aurenix-e-commerce-website.onrender.com/auth/google/aurenix",
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
