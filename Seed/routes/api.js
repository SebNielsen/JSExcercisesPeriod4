/**
 * Created by sebastiannielsen on 07/04/2016.
 */
var express = require("express");
var router = express.Router();

router.get("/names",function(req,res){
    res.status(200).json([{msg: "Peter"}, {msg: "Kurt"},{msg: "Hanne"}]);
});

router.get("/hellos",function(req,res){
    res.status(200).json([{msg: "Hello World" }, {msg: "Hello all"},{msg: "Hello guys"}]);
});

module.exports = router;