const { createHmac, randomBytes } = require("crypto"); // inBuilt to hash pass
const { Schema , model}= require('mongoose');

const userSchema = new Schema ({
    fullName: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    salt: {
        type: String,
    },
    password: {
        type: String,
        required:true,
    },
    profileImageURL: {
        type: String,
        default: "/public/avatar.webp",
    },
    role: {
        type: String,
        enum: ["USER", "ADMIN"],
        default: "USER",
    },
},
{ timestamps: true }
);


userSchema.pre("save", function() { // no arrow function
    const user = this;

    if(!user.isModified("password")) return ; 

    const salt = randomBytes(16).toString("hex");  // salt is random string

    const hashedPassword = createHmac('sha256',salt)// Hmac 
    .update(user.password)
    .digest("hex");// no hext

    this.salt = salt;
    this.password = hashedPassword;

    // next();
});

userSchema.statics.matchPassword = async function(email, password) {
    const user = await this.findOne({ email });
    if(!user) throw new Error('User not found!');

    const salt = user.salt;
    const hashedPassword = user.password;

    const userProvidedHash = createHmac("sha256", salt)
        .update(password)
        .digest("hex");

        if(hashedPassword != userProvidedHash) throw new Error('Incorrect Password')
        return user;
};

const User = model("user",userSchema);

module.exports = User;

