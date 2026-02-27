const fs = require("node:fs");

window.fileBridge = {
  readText(filePath) {
    return fs.readFileSync(filePath, "utf8");
  },
  writeText(filePath, content) {
    fs.writeFileSync(filePath, content, "utf8");
  }
};
