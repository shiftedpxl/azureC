const request = require('request');
const fs = require('fs');

// List of URLs to scrape proxy data from
const urls = [
    "https://api.proxyscrape.com/?request=displayproxies&proxytype=https",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/https_proxies.txt",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/refs/heads/main/proxy_files/socks5_proxies.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/https/https.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks5/socks5.txt",
];

const file = 'proxy.txt';

// Create a Set to store unique proxies
const proxySet = new Set();

// Function to remove the existing file
const removeFile = () => {
    try {
        if (fs.existsSync(file)) {
            fs.unlinkSync(file);
            console.log(`Removed existing ${file}`);
        }
    } catch (err) {
        console.error(`Error removing existing ${file}: ${err}`);
    }
};

// Function to fetch and save data
const fetchAndSave = (url) => {
    return new Promise((resolve, reject) => {
        request.get(url, function (error, response, body) {
            if (error) {
                reject(`Error fetching ${url}: ${error}`);
            } else if (response.statusCode !== 200) {
                reject(`Unexpected status code for ${url}: ${response.statusCode}`);
            } else {
                // Split the body by lines, remove empty strings, and add proxies to the Set
                const proxies = body.split(/\r?\n|\s+/)
                    .map(proxy => proxy.trim())
                    .filter(proxy => proxy !== "");

                proxies.forEach(proxy => proxySet.add(proxy));  // Add proxies to the Set

                console.log(`Fetched and saved data from ${url}`);
                resolve();  // Resolve when done
            }
        });
    });
};

// Main function to execute the process
const main = async () => {
    // Remove existing file before fetching data
    removeFile();

    // Fetch proxies from all URLs
    for (let url of urls) {
        try {
            await fetchAndSave(url);
        } catch (error) {
            console.error(error);
        }
    }

    // Once all URLs are processed, prepare the unique proxies
    const uniqueProxies = Array.from(proxySet).join("\n") + "\n";

    // Write the unique proxies to the file
    fs.writeFile(file, uniqueProxies, (err) => {
        if (err) {
            console.error(`Error writing to file: ${err}`);
        } else {
            // Output the total number of unique proxies
            console.log(`Saved: ${file}`);
            console.log(`Proxies Scraped: ${proxySet.size}`);
        }
    });
};

// Run the main function
main().catch((err) => {
    console.error(`Error during execution: ${err}`);
});
