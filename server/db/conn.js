const mongoose = require("mongoose");
const DB = process.env.URI

mongoose.set('strictQuery', false);
mongoose.connect(DB,{
    useUnifiedTopology: true,
    useNewUrlParser: true
}).then(()=> console.log("MongoDB is connected...")).catch((err)=>{
    console.log(err);
})