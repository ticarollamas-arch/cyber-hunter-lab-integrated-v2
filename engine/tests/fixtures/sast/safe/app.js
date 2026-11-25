const { execFile } = require("child_process");
app.get("/x", (req, res) => { const q = escapeHtml(req.query.q); res.send(`<p>${q}</p>`); });
app.get("/ls", (req, res) => { execFile("ls", [safeDir(req.query.dir)], (e, out) => res.end(out)); });
