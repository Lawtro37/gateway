const http = require('http');
const https = require('https');
const axios = require('axios');
const url = require('url');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { env } = require('process');
const { randomUserAgent } = require('random-useragent');
const HttpsProxyAgent = require('https-proxy-agent');
const doh = require('dohjs');

const GOOGLE_SAFE_BROWSING_API_KEY = process.env.SAFE_API // Replace with your actual API key

async function isUrlSafe(url) {
    const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`;
    const requestBody = {
        client: {
            clientId: "lawtrostudios-gateway",
            clientVersion: "1.5.2"
        },
        threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [
                { url: url }
            ]
        }
    };

    try {
        const response = await axios.post(apiUrl, requestBody).then((response) => response).catch((error) => log("error", error.message));
        log(response.data);
        if (response.data.matches) {
            log("error", 'URL is unsafe:', url);
            return true;
        } 
        return response.data.matches ? false : true;
    } catch (error) {
        log("error", 'Error checking URL with Google Safe Browsing:', error.message);
        return process.env.STRICT == "true" ? false : true; // Assume the URL is unsafe if there's an error
    }
}

let errors = [];
let errorLog = [];
let siteLog = [];

var settings = {
    blocks: {
        blockedSites: [],
        blockedIPs: [],
        blockedUserAgents: [],
        blockedReferers: [],
        blockedCookies: [],
        blockedHeaders: [],
        blockedMethods: [],
    }
}

let passwordHashKey = (Math.random()*1000000000).toString()

var sessionLog = [];

if(process.env.ADMIN_PASSWORD == undefined) {
    log('No admin password found');
    process.env.ADMIN_PASSWORD = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    log('Generated admin password: ' + process.env.ADMIN_PASSWORD);
}

function log(type, message) {
    if(type == 'error') {
        console.error(`[${new Date().toLocaleString()}] [${type.toUpperCase()}] ${message}`);
        sessionLog.push({ time: new Date().toLocaleString(), type, message });
        return;
    } else {
        message = type;
        type = 'info';
    }
    console.log(`[${new Date().toLocaleString()}] [${type.toUpperCase()}] ${message}`);
    sessionLog.push({ time: new Date().toLocaleString(), type, message });
}

log("Safe Browsing API Key: " + GOOGLE_SAFE_BROWSING_API_KEY);

// Ensure the logs directory exists
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

setInterval(async () => {
    log('Saving logs...');

    // Append error log to file
    fs.appendFile(path.join(logsDir, `errorLog_${Date.now()}.json`), JSON.stringify(errorLog), (err) => {
        if (err) {
            log("error", 'Error writing to error log file: ' + err);
        } else {
            log('Error log file updated successfully.');
        }
    });
    errorLog = [];

    // Append site log to file
    fs.appendFile(path.join(logsDir, `siteLog_${Date.now()}.json`), JSON.stringify(siteLog), (err) => {
        if (err) {
            log("error", 'Error writing to site log file: ' + err);
        } else {
            log('Site log file updated successfully.');
        }
    });
    siteLog = [];

    // Append session log to file
    fs.appendFile(path.join(logsDir, `sessionLog_${Date.now()}.json`), JSON.stringify(sessionLog), (err) => {
        if (err) {
            log("error", 'Error writing to session log file: ' + err);
        } else {
            log('Session log file updated successfully.');
        }
    });

    getNewProxy().then((data) => {
        proxyUrl = data;
        log('New Proxy URL: ' + proxyUrl);
    });
}, 1000 * 60 * 5);

async function getNewProxy() {
    const proxyApiUrl = 'http://pubproxy.com/api/proxy?limit=1&format=txt&https=true&level=elite&last_check=60&speed=10&limit=1&country=US';
    try {
        const response = await axios.get(proxyApiUrl);
        if(response.status !== 200 || !response.data || response.data == "No proxy") {  
            log("error", 'Error fetching proxy URL: ' + response.statusText);
            return null; // Return null if an error occurs
        }
        const proxyUrl = response.data;
        log('Proxy URL: ' + proxyUrl);
        return proxyUrl;
    } catch (error) {
        log("error", error.message);
        return null; // Return null if an error occurs
    }
}

headersSent = false;

// Function to get the IP address of the network interface
function getNetworkIP() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const net of interfaces[name]) {
            // Skip over non-IPv4 and internal (i.e., 127.0.0.1) addresses
            if (net.family === 'IPv4' && !net.internal) {
                return net.address;
            }
        }
    }
    return '127.0.0.1'; // Fallback to localhost if no external IP is found
}

// Example proxy URL
let proxyUrl = "160.86.242.23:8080";
const proxy = 'http://pubproxy.com/api/proxy?limit=1&format=txt&https=true&level=elite&last_check=60&speed=10&limit=1&country=US';

getNewProxy().then((data) => {
    proxyUrl = data;
    log('Proxy URL: ' + proxyUrl);
});

const networkIP = "gateway.lawtrostudios.com";
log(`Server IP address: (http(s)://)${networkIP} (${getNetworkIP()})`);

const server = http.createServer(async (req, res) => {
    let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    if(!req.socket.encryipted && process.env.FORCE_HTTPS === 'true') {
        res.writeHead(301, { 'Location': 'https://' + req.headers.host + req.url });
        res.end();
        return;
    }
    if(req.headers['x-forwarded-proto'] === 'http' && process.env.FORCE_HTTPS === 'true') {
        res.writeHead(301, { 'Location': 'https://' + req.headers.host + req.url });
        res.end();
        return;
    }
    //detect if user is valid
    if(req.headers['user-agent'] != "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3") {
        res.writeHead(403, { 'Content-Type': 'text/html' });
        res.end(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Blocked By Safe Brousing</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #ff4d4d; /* Light red background */
                        color: #fff; /* White text for readability */
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }
                    .container {
                        background-color: #fff;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                        text-align: center;
                        color: #333; /* Dark text for the container */
                    }
                    h1 {
                        margin-bottom: 20px;
                        color: #ff4d4d; /* Light red color for the heading */
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Access Denied</h1>
                    <p>suspicus user.</p>
                </div>
            </body>
            </html>
        `);
        return;
    }

    const isSafe = await isUrlSafe(req.url);
    if (!isSafe) {
        res.writeHead(403, { 'Content-Type': 'text/html' });
        res.end(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Blocked By Safe Brousing</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #ff4d4d; /* Light red background */
                        color: #fff; /* White text for readability */
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }
                    .container {
                        background-color: #fff;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                        text-align: center;
                        color: #333; /* Dark text for the container */
                    }
                    h1 {
                        margin-bottom: 20px;
                        color: #ff4d4d; /* Light red color for the heading */
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Access Denied</h1>
                    <p>The requested URL is unsafe and has been blocked.</p>
                </div>
            </body>
            </html>
            `);
        return;
    }
    if (req.url === '/favicon.ico') {
        res.writeHead(200, { 'Content-Type': 'image/x-icon' });
        res.end();
        return;
    }
    if(req.url.startsWith('/run')) {
        log(`ip ${ip} requested run command with password ${req.url.replace('/run', '').replace('/', '')}`);
        if(req.url.replace('/run', '').replace('/', '') == process.env.ADMIN_PASSWORD) {
            log();
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.write('command running');
            res.end();
        } else {
            res.writeHead(401, { 'Content-Type': 'text/html' });
            res.write('Incorrect password');
            res.end();
            return;
        }
        return;
    }
    if(req.url == "/hash") {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.write(passwordHashKey.substring(0, 4)+"******");
        res.end();
        return;
    }
    if(req.url.startsWith('/logs')) {
        if(req.url.replace('/logs', '').replace('/', '') == process.env.ADMIN_PASSWORD) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            let logsHtml = sessionLog.map((log, index) => `
                <div>
                    <pre>${index} : [${log.time}] [${log.type}] ${log.message}</pre>
                </div>
            `).join('');
            const passwordLength = process.env.ADMIN_PASSWORD.length;
            const maskedPassword = '*'.repeat(passwordLength);
            logsHtml = logsHtml.replace(new RegExp(process.env.ADMIN_PASSWORD, 'g'), maskedPassword);
            res.end(logsHtml);
        } else {
            res.writeHead(401, { 'Content-Type': 'text/html' });
            res.write('Incorrect password');
            res.end();
            return;
        }
        return;
    }
    if(req.url.startsWith('/restart')) {
        log(`ip ${ip} requested restart with password ${req.url.replace('/restart', '').replace('/', '')}`);
        if(req.url.replace('/restart', '').replace('/', '') == process.env.ADMIN_PASSWORD) {
            log('Restarting server...');
            server.close(() => {
                log('Server closed successfully');

                // Append error log to file
                fs.appendFile(path.join(logsDir, `errorLog_${Date.now()}.json`), JSON.stringify(errorLog), (err) => {
                    if (err) {
                        log("error", 'Error writing to error log file: ' + err);
                    } else {
                        log('Error log file updated successfully.');
                    }
                });
                errorLog = [];

                // Append site log to file
                fs.appendFile(path.join(logsDir, `siteLog_${Date.now()}.json`), JSON.stringify(siteLog), (err) => {
                    if (err) {
                        log("error", 'Error writing to site log file: ' + err);
                    } else {
                        log('Site log file updated successfully.');
                    }
                });
                siteLog = [];

                // Append session log to file
                fs.appendFile(path.join(logsDir, `sessionLog_${Date.now()}.json`), JSON.stringify(sessionLog), (err) => {
                    if (err) {
                        log("error", 'Error writing to session log file: ' + err);
                    } else {
                        log('Session log file updated successfully.');
                    }
                });

                server.listen(10000, () => {
                    log('Server restarted successfully');
                });

                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.write('Server restarted successfully');
                res.end();
            });
        } else {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.write('Incorrect password');
            res.end();
            return;
        }
        return;
    }
    if(req.url.startsWith('/shutdown')) {
        log(`ip ${ip} requested shutdown with password ${req.url.replace('/shutdown', '').replace('/', '')}`);
        if(req.url.replace('/shutdown', '').replace('/', '') == process.env.ADMIN_PASSWORD) {
            log('Shutting down server...');
            server.close(() => {
                log('Server shut down successfully');

                // Append error log to file
                fs.appendFile(path.join(logsDir, `errorLog_${Date.now()}.json`), JSON.stringify(errorLog), (err) => {
                    if (err) {
                        log("error", 'Error writing to error log file: ' + err);
                    } else {
                        log('Error log file updated successfully.');
                    }
                });
                errorLog = [];

                // Append site log to file
                fs.appendFile(path.join(logsDir, `siteLog_${Date.now()}.json`), JSON.stringify(siteLog), (err) => {
                    if (err) {
                        log("error", 'Error writing to site log file: ' + err);
                    } else {
                        log('Site log file updated successfully.');
                    }
                });
                siteLog = [];

                // Append session log to file
                fs.appendFile(path.join(logsDir, `sessionLog_${Date.now()}.json`), JSON.stringify(sessionLog), (err) => {
                    if (err) {
                        log("error", 'Error writing to session log file: ' + err);
                    } else {
                        log('Session log file updated successfully.');
                    }
                });

                log('Exiting process...');

                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.write('Server restarted successfully');
                res.end();

                process.exit();
            });
        } else {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.write('Incorrect password');
            res.end();
            return;
        }
        return;
    }
    if(req.url.startsWith('/dashboard')) {
        dashboard(req, res);
        return;
    }
    if(req.url === 'https://gateway.lawtrostudios.com') {
        return;
    }
    if (req.url === '/' || req.url === '/fetch') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.write(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Gateway</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f0f0f0;
                        color: #333;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }
                    .container {
                        background-color: #fff;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                        text-align: center;
                    }
                    h1 {
                        margin-bottom: 20px;
                        color: #007BFF;
                    }
                    form {
                        display: flex;
                        flex-direction: column;
                        align-items: center;
                        padding: 20px;
                        width: 100%;
                        max-width: 500px;
                        margin: 0 auto;
                    }
                    input[type="text"] {
                        width: 100%;
                        padding: 10px;
                        margin-bottom: 10px;
                        border: 1px solid #ccc;
                        border-radius: 4px;
                        font-size: 16px;
                        box-sizing: border-box;
                    }
                    input[type="submit"] {
                        padding: 10px 20px;
                        border: none;
                        border-radius: 4px;
                        background-color: #007BFF;
                        color: #fff;
                        font-size: 16px;
                        cursor: pointer;
                        transition: background-color 0.3s;
                    }
                    input[type="submit"]:hover {
                        background-color: #0056b3;
                    }
                    h5 {
                        position: fixed;
                        bottom: 0;
                        left: 0;
                        margin: 20px;
                        text-align: left;
                    }
                    a {
                        color: #007BFF;
                        text-decoration: none;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>The Gateway Project</h1>
                    <p>Welcome to The Gateway Project</p>
                    <p>Gateway is a simple tool that allows you to fetch and display the content of any website through any proxy.</p>
                    <form action="" method="post">
                        <input type="text" name="url" placeholder="Enter URL" required>
                        <input type="submit" value="Fetch">
                    </form>
                    <script>
                        document.querySelector('form').addEventListener('submit', (event) => {
                            event.preventDefault();
                            const url = document.querySelector('input[name="url"]').value;
                            //base64 encode the url
                            url = btoa(url);
                            window.location.href = url;
                        });
                    </script>
                    <p> more info <a href="info">here</a> <p>
                </div>
                <h5>Developed by <a href="https://LawtroStudios.com">Lawtro</a> 🙂👍</h5>
            </body>
            </html>
        `);
        res.end();
        return;
    }
    if (req.url === '/info') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.write(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Gateway Info</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #ff4d4d; /* Light red background */
                        color: #fff; /* White text for readability */
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }
                    .container {
                        background-color: #fff;
                        padding: 20px;
                        maragin-top: 50px;
                        border-radius: 8px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                        text-align: left;
                        color: #333; /* Dark text for the container */
                    }
                    h1 {
                        margin-bottom: 20px;
                        color: #ff4d4d; /* Light red color for the heading */
                    }
                    p {
                        margin-bottom: 10px;
                    }
                    a {
                        color: #007BFF;
                        text-decoration: none;
                    }
                    a:hover {
                        text-decoration: underline;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Gateway Info</h1>
                    <p>the gateway project is nasicly an unoffical proxy that routs trafith though it</p>
                    <p>this allows you to bypass firewalls and other restrictions</p>
                    <p>the gateway still has some restrictions and is not a vpn</p>
                    <p>this is accomplished by fetching the content of the website and rewriting the urls to go through the makeshift proxy</p>
                    <h2>Restrictions</h2>
                    <p>the gateway has some restrictions to keep it safe</p>
                    <p>these restrictions include:</p>
                    <ul>
                        <li>blocking unsafe websites</li>
                        <li>blocking some websites</li>
                        <li>blocking some IP addresses</li>
                    </ul>
                    <h3>temperary restrictions:</h3>
                    <ul>
                        <li>websockets are not currently suported</li>
                        <li>the gateway does not support webRTC</li>
                        <li>the gateway does not support live video playback</li>
                        <li>the gateway does not support live audio playback</li>
                        <li>the gateway is prone to error when changing js requests</li>
                    </ul>
                    <h2>Features</h2>
                    <p>the gateway has some features to help you</p>
                    <p>these features include:</p>
                    <ul>
                        <li>fetching websites</li>
                        <li>fetching the raw content of websites using "/raw/..." in the url</li>
                    </ul>
                    <h2>Terms of Service</h2>
                    <p>by using the gateway you agree to the terms of service</p>
                    <p>the gateway is not responsible for any damage caused by the gateway</p>
                    <p>the gateway is not responsible for any damage caused by the websites you visit</p>
                    <p>the gateway reserves the right to block any website or IP address</p>
                    <p>the gateway reserves the right to block any user IP address</p>
                    <p>the gateway reserves change its policys at any time</p>
                    <h2>Privacy Policy</h2>
                    <p>the gateway ollects data such as visitated websites along with the chorisponding request ip along with any server side errors caused by requests</p>
                    <p>the gateway does not collect any client side errors and/or logs</p>
                    <p>the gateway does not collect any personal data</p>
                    <p>the gateway does not collect any cookies</p>
                    <p>the gateway does not collect any user agent data</p>
                    <p>the gateway does not collect any referer data</p>
                    <p>the gateway does not collect any request headers</p>
                    <p>the gateway does not collect any request methods</p>
                </div>
            </body>
            </html>
        `);
        res.end();
        return;
    }
    if(req.url.startsWith('/raw/')) {
        // deprecated
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.write(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
            </head>
            <body>
                <h1>Raw Content</h1>
                <p>Raw content is not supported in this version of the gateway.</p>
                <p>Due to DNS filter restrictions raw data responses have been deprocated.</p>
                <p>An updated version may be indroduced in the future.</p>
            </body>
            </html>
        `);
        res.end();
        return;

        // ----------------- DEPRECATED -----------------

        // const requestedSite = req.url.slice(5);
        // log(`ip: ${ip} requested raw content of ${requestedSite}`);
        // try {
        //     // Fetch the HTML content from the target UaRL with headers and timeout
        //     const response = await axios.get("https://"+requestedSite, {
        //         headers: {
        //             'User-Agent': req.headers['user-agent'],
        //             'Referer': requestedSite,
        //             'Accept': req.headers['accept'],
        //             'Accept-Language': req.headers['accept-language'],
        //             'Cookie': req.headers['cookie'] // Forward cookies if present
        //         },
        //         httpsAgent: new https.Agent({ rejectUnauthorized: false }), // Handle HTTPS requests
        //         timeout: 15000 // Set timeout to 15 seconds
        //     }).catch((error) => {
        //         log("error", 'Error occurred when fetching raw data: ' + error.message);
        //         res.writeHead(500, { 'Content-Type': 'text/html' });
        //         res.end(`An error occurred: ${error.message}`);
        //         return;
        //     });

        //     // Set the response headers
        //     res.writeHead(200, response.headers);
        //     res.end(response.data);
        //     return;
        // } catch (error) {
        //     log("error", 'Error occurred when fetching raw data: ' + error.message);
        //     res.writeHead(500, { 'Content-Type': 'text/html' });
        //     res.end(`An error occurred: ${error.message}`);
        // }

        // ----------------- DEPRECATED -----------------
    }
    try {
        headersSent = false;
        errors = []; // Reset the errors array on each request
        // Get the requested site URL from the request
        let requestedSite = req.url.slice(1); // Remove the leading slash

        // Ensure the URL starts with 'http://' or 'https://'
        if (!requestedSite.startsWith('http://') && !requestedSite.startsWith('https://')) {
            requestedSite = 'https://' + requestedSite;
        }

        siteLog.push({ip: ip, site: requestedSite});
        log(`ip: ${ip} requested site: ${requestedSite}`);

        if(requestedSite.startsWith('http://')) {
            res.writeHead(301, { 'Location': 'https://' + requestedSite.replace('http://', '') });
            res.end();
            return;
        }

        // Ensure the requested site uses HTTPS
        if (!requestedSite.startsWith('https://')) {
            res.writeHead(301, { 'Location': 'https://' + requestedSite });
            res.end();
            return;
        }

        // Configure the proxy agent
        const proxyAgent = new HttpsProxyAgent(proxyUrl);

        // Randomize User-Agent
        const userAgent = randomUserAgent();

        // Perform DNS over HTTPS query through the proxy
        const dnsResponse = await doh.query({
            name: new URL(requestedSite).hostname,
            type: 'A',
            dns: 'https://cloudflare-dns.com/dns-query', // Using Cloudflare's DoH service
            agent: proxyAgent // Use the proxy agent for the DoH request
        });

        if (!dnsResponse.answers.length) {
            log("error", 'DNS query failed');
            res.writeHead(500, { 'Content-Type': 'text/html' });
            res.end('DNS query failed');
            return;
        }

        const ipAddress = dnsResponse.answers[0].data;

        // Fetch the HTML content from the target URL with headers and timeout
        let response = await axios.get(requestedSite, {
            headers: {
                'User-Agent': userAgent,
                'Referer': requestedSite,
                'Accept': req.headers['accept'], // Forward the Accept header
                'Accept-Language': req.headers['accept-language'],
                'Cookie': req.headers['cookie'] // Forward cookies if present
            },
            httpsAgent: new https.Agent({
                rejectUnauthorized: true // Validate certificates
            }),
            timeout: 15000, // Set timeout to 15 seconds
            proxy: false, // Disable default proxy settings
            resolveWithFullResponse: true,
            lookup: (hostname, options, callback) => {
                callback(null, ipAddress, 4); // Use the resolved IP address
            },
            httpAgent: proxyAgent, // Use the proxy agent for HTTP requests
            httpsAgent: proxyAgent // Use the proxy agent for HTTPS requests
        });

        // Parse the base URL
        const baseUrl = `${url.parse(requestedSite).protocol}//${url.parse(requestedSite).host}`;

        if (response.headers['content-type'].includes('javascript')) {
            // Modify the JavaScript to rewrite all URLs
            let modifiedJs = response.data.replace(/(['"])(https?:\/\/[^'"]+|\/[^'"]+)(['"])/g, (match, p1, p2, p3, offset, string) => {
                // Check if the match is inside a replace function
                const beforeMatch = string.slice(0, offset);
                const isInReplaceFunction = /replace\s*\(\s*['"]/.test(beforeMatch);

                if (isInReplaceFunction) {
                    return match; // Do not modify if inside a replace function
                }

                let rewrittenUrl;
                if ((p2.startsWith('http') || p2.startsWith('https')) && p2.length > 8) {
                    // Rewrite absolute URLs only if there is something after http or https
                    const absoluteUrl = p2.startsWith('//') ? `http:${p2}` : p2;
                    rewrittenUrl = `https://${networkIP}/${absoluteUrl}`;
                } else {
                    // Rewrite relative URLs
                    const baseUrl = `${url.parse(requestedSite).protocol}//${url.parse(requestedSite).host}`;
                    const relativeUrl = p2.startsWith('/') ? p2 : `/${p2}`;
                    rewrittenUrl = `https://${networkIP}/${baseUrl}${relativeUrl}`;
                }
                log(`${p1}${rewrittenUrl}${p3}`);
                return `${p1}${rewrittenUrl}${p3}`;
            });
        
            // Set the response headers
            headersSent = true;
            res.writeHead(200, { 'Content-Type': 'application/javascript' });
            res.end(modifiedJs);
            return;
        }

        if (response.headers['content-type'].includes("text/css")) {
            // Ensure response.data is a string
            const cssData = response.data.toString();
        
            // Modify the CSS to rewrite all URLs
            let modifiedCss = cssData.replace(/url\(['"]?([^'")]+)['"]?\)/g, (match, p1) => {
                if (p1.startsWith('http') || p1.startsWith('https') || p1.startsWith('//')) {
                    // Rewrite absolute URLs
                    const absoluteUrl = p1.startsWith('//') ? `http:${p1}` : p1;
                    return `url(https://${networkIP}/${absoluteUrl})`;
                }
                // Rewrite relative URLs
                const relativeUrl = p1.startsWith('/') ? p1 : `/${p1}`;
                return `url(https://${networkIP}${baseUrl}${relativeUrl})`;
            });
        
            // Set the response headers
            if (!headersSent) {
                res.writeHead(200, { 'Content-Type': 'text/css' });
                res.end(modifiedCss);
                headersSent = true;
                return;
            }
        }

        // Check if the content type is not HTML
        if (!response.headers['content-type'].includes('text/html')) {
            if (!headersSent) {
                const contentType = response.headers['content-type'] || 'application/octet-stream';
                
                if (contentType.includes('application/json')) {
                    log('JSON detected');
                    res.writeHead(200, { 'Content-Type': contentType });
                    res.end(JSON.stringify(response.data));
                    headersSent = true;
                    return;
                } else if (contentType.includes('image/')) {
                    log('Image detected');
                    const expiresDate = new Date();
                    expiresDate.setFullYear(expiresDate.getFullYear() + 1);
                
                    const headers = {
                        'Content-Type': response.headers['content-type'],
                        'Expires': expiresDate.toUTCString(),
                    };
                
                    // Conditionally add headers if they exist
                    if (response.headers['content-length']) {
                        headers['Cache-Control'] = response.headers['cache-control'];
                    }
                    if (response.headers['last-modified']) {
                        headers['Last-Modified'] = response.headers['last-modified'];
                    }
                    if (response.headers['cache-control']) {
                        headers['Cache-Control'] = response.headers['cache-control'];
                    }
                    if (response.headers['last-modified']) {
                        headers['Last-Modified'] = response.headers['last-modified'];
                    }
                    if (response.headers['accept-ranges']) {
                        headers['Accept-Ranges'] = response.headers['accept-ranges'];
                    }
                    if (response.headers['cross-origin-resource-policy']) {
                        headers['Cross-Origin-Resource-Policy'] = response.headers['cross-origin-resource-policy'];
                    }
                    if (response.headers['x-content-type-options']) {
                        headers['X-Content-Type-Options'] = response.headers['x-content-type-options'];
                    }
                    if (response.headers['x-xss-protection']) {
                        headers['X-XSS-Protection'] = response.headers['x-xss-protection'];
                    }
                
                    res.writeHead(200, headers);
                    res.end(Buffer.from(response.data, 'binary'));
                    headersSent = true;
                    return;
                } else {
                    res.writeHead(200, response.headers);
                    res.end(response.data);
                    headersSent = true;
                    return;
                }
            }
        }

        // Modify the HTML to rewrite all URLs
        let modifiedHtml = response.data.replace(/(src|href|srcset|action|content|component-url)=['"]?([^'"\s]*)['"]?/g, (match, p1, p2) => {
            if (p1 === 'srcset') {
                // Handle srcset attribute
                return `${p1}="${p2.split(',').map(src => {
                    const [url, descriptor] = src.trim().split(' ');
                    if (url.endsWith('.png') || url.endsWith('.jpg') || url.endsWith('.jpeg') || url.endsWith('.gif') || url.endsWith('.webp') || url.endsWith('.ico') || url.startsWith('data:image')) {
                        if (!url.startsWith('http') && !url.startsWith('https') && !url.startsWith('//') && !url.startsWith('data:image')) {
                            // Make relative URLs absolute
                            const absoluteUrl = url.startsWith('/') ? `${baseUrl}${url}` : `${baseUrl}/${url}`;
                            return `${absoluteUrl} ${descriptor}`;
                        }
                        return `${url} ${descriptor}`;
                    }
                    if ((url.startsWith('http') || url.startsWith('https') || url.startsWith('//')) && url.length > 8) {
                        const absoluteUrl = url.startsWith('//') ? `http:${url}` : url;
                        return `https://${networkIP}/${absoluteUrl} ${descriptor}`;
                    }
                    const relativeUrl = url.startsWith('/') ? url : `/${url}`;
                    return `https://${networkIP}/${baseUrl + relativeUrl} ${descriptor}`;
                }).join(', ')}"`;
            } else {
                if (p2.endsWith('.png') || p2.endsWith('.jpg') || p2.endsWith('.jpeg') || p2.endsWith('.gif') || p2.endsWith('.webp') || p2.endsWith('.ico') || p2.startsWith('data:image')) {
                    if (!p2.startsWith('http') && !p2.startsWith('https') && !p2.startsWith('//') && !p2.startsWith('data:image')) {
                        // Make relative URLs absolute
                        const absoluteUrl = p2.startsWith('/') ? `${baseUrl}${p2}` : `${baseUrl}/${p2}`;
                        return `${p1}="${absoluteUrl}"`;
                    }
                    return match;
                }
                if ((p2.startsWith('http') || p2.startsWith('https') || p2.startsWith('//')) && p2.length > 8) {
                    // Rewrite absolute URLs only if there is something after http or https
                    const absoluteUrl = p2.startsWith('//') ? `http:${p2}` : p2;
                    return `${p1}="https://${networkIP}/${absoluteUrl}"`;
                }
                // Rewrite relative URLs
                const relativeUrl = p2.startsWith('/') ? p2 : `/${p2}`;
                return `${p1}="https://${networkIP}/${baseUrl + relativeUrl}"`;
            }
        });

        // Handle <style> tags
        modifiedHtml = modifiedHtml.replace(/<style[^>]*>([\s\S]*?)<\/style>/gi, (match, cssContent) => {
            let modifiedCss = cssContent.replace(/url\(['"]?([^'")]+)['"]?\)/g, (match, p1) => {
                if (p1.endsWith('.png') || p1.endsWith('.jpg') || p1.endsWith('.jpeg') || p1.endsWith('.gif') || p1.endsWith('.webp') || p1.endsWith('.ico') || p1.startsWith('data:image')) {
                    if (p1 === 'data:image/gif;base64,R0lGODlhAQABAIAAAP///////yH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==') {
                        return match;
                    }
                    if (!p1.startsWith('http') && !p1.startsWith('https') && !p1.startsWith('//') && !p1.startsWith('data:image')) {
                        // Make relative URLs absolute
                        const absoluteUrl = p1.startsWith('/') ? `${baseUrl}${p1}` : `${baseUrl}/${p1}`;
                        return `url(${absoluteUrl})`;
                    }
                    return match;
                }
                if ((p1.startsWith('http') || p1.startsWith('https') || p1.startsWith('//')) && p1.length > 8) {
                    // Rewrite absolute URLs only if there is something after http or https
                    const absoluteUrl = p1.startsWith('//') ? `http:${p1}` : p1;
                    return `url(https://${networkIP}/${absoluteUrl})`;
                }
                // Rewrite relative URLs
                const relativeUrl = p1.startsWith('/') ? p1 : `/${p1}`;
                return `url(https://${networkIP}/${baseUrl}${relativeUrl})`;
            });
            return `<style>${modifiedCss}</style>`;
        });

        // Handle style attributes
        modifiedHtml = modifiedHtml.replace(/style=['"]([^'"]*)['"]/gi, (match, styleContent) => {
            let modifiedStyle = styleContent.replace(/url\(['"]?([^'")]+)['"]?\)/g, (match, p1) => {
                if (p1.endsWith('.png') || p1.endsWith('.jpg') || p1.endsWith('.jpeg') || p1.endsWith('.gif') || p1.endsWith('.webp') || p1.endsWith('.ico') || p1.startsWith('data:image')) {
                    if (p1 === 'data:image/gif;base64,R0lGODlhAQABAIAAAP///////yH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==') {
                        return match;
                    }
                    if (!p1.startsWith('http') && !p1.startsWith('https') && !p1.startsWith('//') && !p1.startsWith('data:image')) {
                        // Make relative URLs absolute
                        const absoluteUrl = p1.startsWith('/') ? `${baseUrl}${p1}` : `${baseUrl}/${p1}`;
                        return `url(${absoluteUrl})`;
                    }
                    return match;
                }
                if ((p1.startsWith('http') || p1.startsWith('https') || p1.startsWith('//')) && p1.length > 8) {
                    // Rewrite absolute URLs only if there is something after http or https
                    const absoluteUrl = p1.startsWith('//') ? `http:${p1}` : p1;
                    return `url(https://${networkIP}/${absoluteUrl})`;
                }
                // Rewrite relative URLs
                const relativeUrl = p1.startsWith('/') ? p1 : `/${p1}`;
                return `url(https://${networkIP}/${baseUrl}${relativeUrl})`;
            });
            return `style="${modifiedStyle}"`;
        });

        // Set the response headers
        if (!headersSent) {
            res.writeHead(200, {
                'Content-Type': 'text/html',
                'Referrer-Policy': `origin-when-cross-origin`,
                'Referrer': requestedSite
            });
            res.end(modifiedHtml);
            headersSent = true;
            return;
        }
    } catch (error) {
        errors.push({ error: error, ip: ip, site: req.url.slice(1) });
        errorLog.push(error);

        // Extract the line number from the error stack
        const errorLine = error.stack.split('\n')[1].trim();

        // Log the error for debugging purposes
        log("error", 'Error occurred:' + error.message + " on " + errorLine);

        // Set the response status code and headers
        // if (!headersSent) {
        //     res.writeHead(500, { 'Content-Type': 'text/html' });

        // Generate the HTML for all errors
        const errorDetailsHtml = errors.map((err, index) => `
            <div class="error-item">
                <pre>${err.error.message}</pre>
                <pre>Line: ${err.error.stack.split('\n')[1].trim()}</pre>
            </div>
        `).join('');

        // Send a detailed error message as the response
        res.end(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Gateway Error</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f8d7da;
                        color: #721c24;
                        margin: 0;
                        padding: 0;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                    }
                    .container {
                        text-align: center;
                        background-color: #f8d7da;
                        border: 1px solid #f5c6cb;
                        padding: 20px;
                        border-radius: 5px;
                    }
                    h1 {
                        font-size: 2em;
                        margin-bottom: 0.5em;
                    }
                    p {
                        margin: 0.5em 0;
                    }
                    .error-details {
                        margin-top: 1em;
                        padding: 10px;
                        background-color: #f5c6cb;
                        border-radius: 5px;
                        text-align: left;
                    }
                    .error-details pre {
                        margin: 0;
                        white-space: pre-wrap;
                        word-wrap: break-word;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Something went wrong</h1>
                    <p>We encountered an error while processing your request.</p>
                    <div class="error-details">
                        <h2>Error Details:</h2>
                        ${errorDetailsHtml}
                    </div>
                </div>
            </body>
            </html>
        `);
    }//}
});

server.listen(process.eventNames.PORT || 443, () => {
    log(`Server is listening on port ${process.eventNames.PORT || 443} and IP address ${process.eventNames.PORT || 443} at ${new Date().toLocaleString()}`);
});

process.on('uncaughtException', (err) => {
    const errorLine = err.stack.split('\n')[1].trim();
    log("error", 'FAITAL ERROR: ' + err + " on " + errorLine);
    errorLog.push(err);
    // Append error log to file
    fs.appendFile(path.join(logsDir, `FAITAL_ERROR_errorLog - ${Date.now()}.json`), JSON.stringify(errorLog), (err) => {
        if (err) {
            log("error" + 'Error writing to error log file: ' + err);
        } else {
            log('Error log file updated successfully.');
        }
    });
    errorLog = [];

    // Append site log to file
    fs.appendFile(path.join(logsDir, `FAITAL_ERROR_siteLog - ${Date.now()}.json`), JSON.stringify(siteLog), (err) => {
        if (err) {
            log("error" + 'Error writing to site log file: ' + err);
        } else {
            log('Site log file updated successfully.');
        }
    });
    siteLog = [];

    // Append session log to file
    fs.appendFile(path.join(logsDir, `sessionLog_${Date.now()}.json`), JSON.stringify(sessionLog), (err) => {
        if (err) {
            log("error", 'Error writing to session log file: ' + err);
        } else {
            log('Session log file updated successfully.');
        }
    });

    // attempt to close the server and restart
    server.close(() => {
        log('Server closed due to uncaught exception. Restarting...');
        try {
            server.listen(3000, () => {
                log(`Server restarted at ${networkIP}`);
            });
        } catch (error) {
            log("error", 'Failed to restart server: ' + error);
            log("error", 'Exiting process...');

            // Append session log to file
            fs.appendFile(path.join(logsDir, `sessionLog_${Date.now()}.json`), JSON.stringify(sessionLog), (err) => {
                if (err) {
                    log("error", 'Error writing to session log file: ' + err);
                } else {
                    log('Session log file updated successfully.');
                }
            });
        }
    });
});

//-----------------Dashboard-----------------

function dashboard(req, res) {
    let html;
    const body = req.url.replace('/dashboard', '').replace('/', '');

    if (body == "") {
        log(`ip: ${req.headers['x-forwarded-for'] || req.connection.remoteAddress} requested dashboard`);
        html = `
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>VERIFY PASSWORD</title>
        <script>
            (function() {
                const adminPassword = prompt("Enter admin password");
                fetch('/dashboard/'+adminPassword, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ password: adminPassword }) // Ensure the body is a JSON string
                }).then(res => {
                    if (res.status === 200) {
                        console.log("success");
                        res.text().then(text => document.write(text));
                    } else {
                        document.write('Wrong password');
                    }
                });
            })();
        </script>
    </head>
    <body>
        Verify Admin Password
    </body>`;
    } else {
        if (!body) {
            html = 'Incorrect password';
            log(`ip: ${req.headers['x-forwarded-for'] || req.connection.remoteAddress} entered incorrect password`);
        }
        if (body === process.env.ADMIN_PASSWORD) {
            log(`ip: ${req.headers['x-forwarded-for'] || req.connection.remoteAddress} logged in as admin`);
            let logsHtml = sessionLog.map((log, index) => `
                <div>
                    <pre>${index} : [${log.time}] [${log.type}] ${log.message}</pre>
                </div>
            `).join('');
            const passwordLength = process.env.ADMIN_PASSWORD.length;
            const maskedPassword = '*'.repeat(passwordLength);
            logsHtml = logsHtml.replace(new RegExp(process.env.ADMIN_PASSWORD, 'g'), maskedPassword);
            html = `
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Dashboard - Gateway</title>
            </head>
            <body>
                <h1>Dashboard</h1>
                <p>Logged in as admin</p>
                <script>
                    passwordHashKey = "${passwordHashKey}";
                    password = prompt("re-enter admin password for continous logging");
                    fetch('/logs/'+password, { method: 'POST', body: {} }).then(res => {
                            if(res.status !== 200) {
                                document.getElementById("logs").innerHTML = "Wrong password";
                                password = prompt("Wrong password | re-enter admin password for continous logging");
                            } else {
                                return res.text();
                            }
                        }).then(body => {
                            document.getElementById("logs").innerHTML = body + '<!--<input type="text" id="command" placeholder="enter command"><button onclick="fetch("/run/"+prompt("Enter admin password"), { method: "POST" })">run</button>;-->'
                        })
                    setInterval(() => {
                        fetch('/hash', { method: 'POST', body: {} }).then(res => {
                            if(res.status !== 200) {
                                return res.text()
                            }
                        }).then(body => {
                            if(body.substring(0, 4) != passwordHashKey.substring(0, 4)) {
                                console.log("server down");
                                document.getElementById("logs").innerHTML = "Server down | reloading in 30 seconds [refresh page to reload now] | hash mismatch";
                                setTimeout(() => {
                                    window.location.reload();
                                }, 30000);
                            }    
                        })
                        getLogs()
                    }, 10000);
                    function getLogs() {
                        fetch('/logs/'+password, { method: 'POST', body: {} }).then(res => {
                            if(res.status !== 200) {
                                document.getElementById("logs").innerHTML = "Wrong password";
                            } else {
                                return res.text();
                            }
                        }).then(body => {
                            document.getElementById("logs").innerHTML = body + '<!--<input type="text" id="command" placeholder="enter command"><button onclick="fetch("/run/"+prompt("Enter admin password"), { method: "POST" })">run</button>-->' + '<br>Last updated at ' + new Date().toLocaleString();
                        })
                    }
                </script>
                <h2>Session log:</h2>
                <div id="logs">
                    ${logsHtml}
                </div>
                <button onclick="fetch('/logs/'+prompt('Enter admin password'), { method: 'POST', body: {} })">Reload</button>
                <!-- <h2>Settings   [WARNING] (do not touch unless you know what you are doing) </h2>
                <textarea id="settings">
                </textarea> -->
                <h2>Server Operations</h2>
                <button onclick="fetch('/restart/'+prompt('Enter admin password'), { method: 'POST', body: {} }).then(res => {getLogs()})">Restart</button>
                <button onclick="fetch('/shutdown/'+prompt('Enter admin password'), { method: 'POST', body: {} }) }).then(res => {getLogs()})">Shutdown</button>
            </body>`;
        } else {
            html = 'Incorrect password';
            log(`ip: ${req.headers['x-forwarded-for'] || req.connection.remoteAddress} entered incorrect password`);
        }
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.write(html);
    res.end();
}
