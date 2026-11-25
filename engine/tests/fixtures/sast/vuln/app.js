const { exec } = require("child_process");
app.get("/x", (req, res) => { res.send("<p>" + req.query.q + "</p>"); });
app.get("/ls", (req, res) => { exec("ls " + req.query.dir, (e, out) => res.end(out)); });
