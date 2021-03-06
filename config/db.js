const mongoose = require('mongoose')
const config = require('config')

const db = config.get('mongoURI')

const connectDB = async () => {
    try { 
        await mongoose.connect(db, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        })

        console.log('MongoDB has connected...')
    } catch(err) {
        console.error(err.mesage)
        // Exit process with failure
        process.exit(1)
    }
}

module.exports = connectDB