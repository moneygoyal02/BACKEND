import mongoose, {Schema} from "mongoose";
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"

const userSchema = new Schema({

    username: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true, 
        index: true  // optimised for search
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowecase: true,
        trim: true, 
    },
    fullName: {
        type: String,
        required: true,
        trim: true, 
        index: true
    },
    avatar: {
        type: String, // cloudinary url
        required: true,
    },
    coverImage: {
        type: String, // cloudinary url
    },
    watchHistory: [
        {
            type: Schema.Types.ObjectId,
            ref: "Video"
        }
    ],
    password: {
        type: String,
        required: [true, 'Password is required']
    },
    refreshToken: {
        type: String
    }
},{timestamps: true})


userSchema.pre("save", async function(next) {
    if(!this.isModified("password")) return next();
    this.password = await bcrypt.hash(this.password, 10)
    next()
})

userSchema.methods.isPasswordCorrect = async function(password){
    return await bcrypt.compare(password, this.password)
}

userSchema.methods.generateAccessToken = function(){
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            username: this.username,
            fullName: this.fullName
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}
userSchema.methods.generateRefreshToken = function(){
    return jwt.sign(
        {
            _id: this._id,
            
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}

export const User = mongoose.model("User", userSchema)

/*Access Token
Definition:
An access token is a short-lived token that allows a user to access specific resources or 
perform certain actions. It is usually included in the headers of API requests to authenticate the user.

Characteristics:

Short lifespan (usually minutes to hours).
Used to access protected resources.
Example:
Imagine you log in to a website. After logging in, the server gives you an access token. 
You use this token to access pages like your profile or dashboard. When you click on these pages,
 your browser sends the access token to the server to prove that you're logged in and allowed to see the content.

Refresh Token
Definition:
A refresh token is a long-lived token that is used to obtain a new access token when the current 
access token expires. It is not sent with every request but is stored securely by the client.

Characteristics:

Long lifespan (usually days, weeks, or months).
Used to get a new access token without re-entering login credentials.
Example:
Continuing from the previous example, when your access token expires after an hour, you don't 
want to log in again. Instead, your browser uses the refresh token to ask the server for a new
 access token. The server verifies the refresh token and provides a new access token, allowing 
 you to continue accessing protected pages without logging in again.

Simple Scenario Example
Logging In:

You log in to a food delivery app.
The server sends you an access token (valid for 1 hour) and a refresh token (valid for 30 days).
Using the Access Token:

For the next hour, you use the app to browse restaurants, place orders, etc.
Each API request includes the access token to verify your identity.
Access Token Expiration:

After 1 hour, the access token expires.
You try to place another order, but your access token is no longer valid.
Using the Refresh Token:

Your app automatically sends the refresh token to the server.
The server verifies the refresh token and issues a new access token (valid for another hour).
Continuing Use:

You continue using the app without interruption.
This cycle repeats until the refresh token expires (after 30 days), at which point you'll need to log in again.
This process ensures that you have secure, short-term access to resources while minimizing the need 
to re-enter your credentials frequently.   

The reason we use access tokens instead of directly using the refresh token for every request is based on security best practices. Here are some key points:

Security of Refresh Tokens:

Refresh tokens are long-lived and provide a means to obtain new access tokens without re-entering login credentials. If a refresh token were used directly for API requests, its exposure could result in long-term unauthorized access if stolen.
By using access tokens for short-term access, the risk of a stolen token is limited because it will expire soon, whereas a stolen refresh token would give long-term access.
Limited Scope of Access Tokens:

Access tokens are scoped for specific actions or resources and have a short lifespan. This means they are less risky to use for everyday API requests, limiting the impact of potential misuse.
Refresh tokens, on the other hand, are designed only for requesting new access tokens, not for performing other actions like fetching restaurant data. This separation of responsibility adds another layer of security.
Reduced Attack Surface:

Since refresh tokens are more powerful (they can generate new access tokens), they are usually stored securely and only used when absolutely necessary.
Keeping the refresh token use infrequent (only for refreshing access tokens) limits how often it is exposed or transferred over the network, reducing the risk of it being intercepted.
Access Tokens are More Efficient:

Access tokens are usually lighter (smaller in size) and optimized for fast and frequent access to protected resources.
Using the refresh token for every request would introduce unnecessary overhead for the server and increase the complexity of token validation.


1. JWT (JSON Web Token):
Purpose: JWT is used for securely transmitting information between parties as a JSON object. It's commonly used for authentication (like session tokens) and information exchange.
How it works:
A JWT consists of three parts: Header, Payload, and Signature.
The token is created on the server after the user successfully logs in, and the token is sent back to the client.
The client sends this token with each request to access protected routes or resources.
JWT is stateless, meaning the server doesn't need to store the token in the session. Instead, it's self-contained, as it carries its own authentication claims (like user info or roles).
Use case: Mostly used in web applications for stateless authentication. The client stores the JWT, usually in localStorage or a cookie, and passes it with each request.
Security: JWT itself is signed (using HMAC or RSA) to ensure the authenticity of the claims, but it is not encrypted by default, so sensitive data should not be placed in the payload without encryption.
2. bcrypt:
Purpose: bcrypt is a password hashing function. It is used to securely hash and store passwords in databases.
How it works:
When a user creates a password, bcrypt hashes the password with a salt, which is a random value that is added to the password before hashing to prevent pre-computed attacks (rainbow tables).
When the user tries to log in, bcrypt checks if the hashed version of the password they provided matches the one stored in the database.
bcrypt is slow by design to mitigate brute-force attacks, and it allows for setting a work factor (how many iterations it will take).
Use case: Used for password hashing and verification to ensure that stored passwords are protected in case of a database breach.
Security: bcrypt ensures the password is stored in a hashed form, and the hashing process is resistant to brute-force attacks.
Key Differences:
JWT is for authentication and session management, while bcrypt is used for secure password storage.
JWT involves creating tokens that can be verified and used to validate a user’s identity, while bcrypt hashes passwords to prevent storing them in plain text.

*/
