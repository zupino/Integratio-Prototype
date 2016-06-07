cordova.define('cordova/plugin_list', function(require, exports, module) {
module.exports = [
    {
        "file": "plugins/cz.blocshop.socketsforcordova/socket.js",
        "id": "cz.blocshop.socketsforcordova.Socket",
        "clobbers": [
            "window.Socket"
        ]
    }
];
module.exports.metadata = 
// TOP OF METADATA
{
    "cordova-plugin-whitelist": "1.2.2",
    "cz.blocshop.socketsforcordova": "1.1.0"
};
// BOTTOM OF METADATA
});