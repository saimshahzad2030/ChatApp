
const jwt = require('../middleware/jwt.js')

const bcrypt = require('bcrypt');
const userController = {
    async signup(req, res) {
        try {
            const { email, password } = req.body;
            if (!email || !password) {
                return res.status(404).json({ message: "all fields required" })
            }
            // Check if the user already exists
            const exitingUser = await User.findOne({ email });
            const existingBlockedUser = await BlockedUser.findOne({ email });
            if (exitingUser) {
                return res.status(409).json({ message: "email already exist" })
            }
            else if(existingBlockedUser){
                return res.status(409).json({ message: "You are blocked user and u cannot create your account" })

            }
            else{
                // Hash the password
            const hashPaswd = await bcrypt.hash(password, 10)
            //create user
            const newUser = new User({

                email,
                password: hashPaswd,

            })
            await newUser.save()

            const token = jwt.sign(req.body, password)
            res.status(200).json({ token })
            }
        }
        catch (error) {
            res.status(520).json({ message: "internal server error", error: error.message })
        }

    },
    async login(req, res) {
        try {
            const { email, password } = req.body;
            if (!email || !password) {
                return res.status(401).json({ message: "Enter Password & email both" })

            }
            //find user
            else {
                const user = await User.findOne({ email })
                const isPaswd = await bcrypt.compare(password, user.password)
                // console.log(user)
                if (!user) {
                    return res.status(401).json({ message: "invalid email or password" })
                }
                //compare password
                else if (!isPaswd) {
                    return res.status(401).json({ message: "wrong password" })
                }
                //generate jwt

                // const authHeader = req.headers.authorization;

                else {
                    const token = jwt.sign(req.body, password)
                    res.status(200).send(token)
                }
            }
        }
        catch (error) {
            return res.status(520).json({ message: "internal server error", error: error.message })
        }
    }
}


module.exports = userController