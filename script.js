const crackBtn    = document.getElementById("crackBtn");
const stopBtn     = document.getElementById("stopBtn");
const hashInput   = document.getElementById("hashInput");
const statusEl    = document.getElementById("status");
const progressBar = document.getElementById("progressBar");
const resultsBody = document.getElementById("resultsBody");

let stopFlag = false;
let isRunning = false;

function hex(buffer) {
  return [...new Uint8Array(buffer)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha1(data) {
  return hex(await crypto.subtle.digest("SHA-1", data));
}
async function sha256(data) {
  return hex(await crypto.subtle.digest("SHA-256", data));
}
async function sha384(data) {
  return hex(await crypto.subtle.digest("SHA-384", data));
}
async function sha512(data) {
  return hex(await crypto.subtle.digest("SHA-512", data));
}

function md5(string) {
  function safeAdd(x, y) {
    const lsw = (x & 0xffff) + (y & 0xffff);
    const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xffff);
  }
  function bitRotateLeft(num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt));
  }
  function md5cmn(q, a, b, x, s, t) {
    return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
  }
  function md5ff(a, b, c, d, x, s, t) {
    return md5cmn((b & c) | (~b & d), a, b, x, s, t);
  }
  function md5gg(a, b, c, d, x, s, t) {
    return md5cmn((b & d) | (c & ~d), a, b, x, s, t);
  }
  function md5hh(a, b, c, d, x, s, t) {
    return md5cmn(b ^ c ^ d, a, b, x, s, t);
  }
  function md5ii(a, b, c, d, x, s, t) {
    return md5cmn(c ^ (b | ~d), a, b, x, s, t);
  }
  function binlMD5(x, len) {
    x[len >> 5] |= 0x80 << (len % 32);
    x[(((len + 64) >>> 9) << 4) + 14] = len;
    let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
    for (let i = 0; i < x.length; i += 16) {
      const olda = a, oldb = b, oldc = c, oldd = d;
      a = md5ff(a, b, c, d, x[i], 7, -680876936);
      d = md5ff(d, a, b, c, x[i+1], 12, -389564586);
      c = md5ff(c, d, a, b, x[i+2], 17, 606105819);
      b = md5ff(b, c, d, a, x[i+3], 22, -1044525330);
      a = md5ff(a, b, c, d, x[i+4], 7, -176418897);
      d = md5ff(d, a, b, c, x[i+5], 12, 1200080426);
      c = md5ff(c, d, a, b, x[i+6], 17, -1473231341);
      b = md5ff(b, c, d, a, x[i+7], 22, -45705983);
      a = md5ff(a, b, c, d, x[i+8], 7, 1770035416);
      d = md5ff(d, a, b, c, x[i+9], 12, -1958414417);
      c = md5ff(c, d, a, b, x[i+10], 17, -42063);
      b = md5ff(b, c, d, a, x[i+11], 22, -1990404162);
      a = md5ff(a, b, c, d, x[i+12], 7, 1804603682);
      d = md5ff(d, a, b, c, x[i+13], 12, -40341101);
      c = md5ff(c, d, a, b, x[i+14], 17, -1502002290);
      b = md5ff(b, c, d, a, x[i+15], 22, 1236535329);
      a = md5gg(a, b, c, d, x[i+1], 5, -165796510);
      d = md5gg(d, a, b, c, x[i+6], 9, -1069501632);
      c = md5gg(c, d, a, b, x[i+11], 14, 643717713);
      b = md5gg(b, c, d, a, x[i], 20, -373897302);
      a = md5gg(a, b, c, d, x[i+5], 5, -701558691);
      d = md5gg(d, a, b, c, x[i+10], 9, 38016083);
      c = md5gg(c, d, a, b, x[i+15], 14, -660478335);
      b = md5gg(b, c, d, a, x[i+4], 20, -405537848);
      a = md5gg(a, b, c, d, x[i+9], 5, 568446438);
      d = md5gg(d, a, b, c, x[i+14], 9, -1019803690);
      c = md5gg(c, d, a, b, x[i+3], 14, -187363961);
      b = md5gg(b, c, d, a, x[i+8], 20, 1163531501);
      a = md5gg(a, b, c, d, x[i+13], 5, -1444681467);
      d = md5gg(d, a, b, c, x[i+2], 9, -51403784);
      c = md5gg(c, d, a, b, x[i+7], 14, 1735328473);
      b = md5gg(b, c, d, a, x[i+12], 20, -1926607734);
      a = md5hh(a, b, c, d, x[i+5], 4, -378558);
      d = md5hh(d, a, b, c, x[i+8], 11, -2022574463);
      c = md5hh(c, d, a, b, x[i+11], 16, 1839030562);
      b = md5hh(b, c, d, a, x[i+14], 23, -35309556);
      a = md5hh(a, b, c, d, x[i+1], 4, -1530992060);
      d = md5hh(d, a, b, c, x[i+4], 11, 1272893353);
      c = md5hh(c, d, a, b, x[i+7], 16, -155497632);
      b = md5hh(b, c, d, a, x[i+10], 23, -1094730640);
      a = md5hh(a, b, c, d, x[i+13], 4, 681279174);
      d = md5hh(d, a, b, c, x[i], 11, -358537222);
      c = md5hh(c, d, a, b, x[i+3], 16, -722521979);
      b = md5hh(b, c, d, a, x[i+6], 23, 76029189);
      a = md5hh(a, b, c, d, x[i+9], 4, -640364487);
      d = md5hh(d, a, b, c, x[i+12], 11, -421815835);
      c = md5hh(c, d, a, b, x[i+15], 16, 530742520);
      b = md5hh(b, c, d, a, x[i+2], 23, -995338651);
      a = md5ii(a, b, c, d, x[i], 6, -198630844);
      d = md5ii(d, a, b, c, x[i+7], 10, 1126891415);
      c = md5ii(c, d, a, b, x[i+14], 15, -1416354905);
      b = md5ii(b, c, d, a, x[i+5], 21, -57434055);
      a = md5ii(a, b, c, d, x[i+12], 6, 1700485571);
      d = md5ii(d, a, b, c, x[i+3], 10, -1894986606);
      c = md5ii(c, d, a, b, x[i+10], 15, -1051523);
      b = md5ii(b, c, d, a, x[i+1], 21, -2054922799);
      a = md5ii(a, b, c, d, x[i+8], 6, 1873313359);
      d = md5ii(d, a, b, c, x[i+15], 10, -30611744);
      c = md5ii(c, d, a, b, x[i+6], 15, -1560198380);
      b = md5ii(b, c, d, a, x[i+13], 21, 1309151649);
      a = md5ii(a, b, c, d, x[i+4], 6, -145523070);
      d = md5ii(d, a, b, c, x[i+11], 10, -1120210379);
      c = md5ii(c, d, a, b, x[i+2], 15, 718787259);
      b = md5ii(b, c, d, a, x[i+9], 21, -343485551);
      a = safeAdd(a, olda); b = safeAdd(b, oldb);
      c = safeAdd(c, oldc); d = safeAdd(d, oldd);
    }
    return [a, b, c, d];
  }
  function str2binl(str) {
    const bin = [];
    for (let i = 0; i < str.length * 8; i += 8) {
      bin[i >> 5] |= (str.charCodeAt(i / 8) & 0xff) << (i % 32);
    }
    return bin;
  }
  function binl2hex(binarray) {
    const hexTab = "0123456789abcdef";
    let str = "";
    for (let i = 0; i < binarray.length * 4; i++) {
      str += hexTab.charAt((binarray[i >> 2] >> ((i % 4) * 8 + 4)) & 0xf) +
             hexTab.charAt((binarray[i >> 2] >> ((i % 4) * 8)) & 0xf);
    }
    return str;
  }
  return binl2hex(binlMD5(str2binl(string), string.length * 8));
}

function detectAlgos(hash) {
  const h = hash.trim().toLowerCase();
  if (h.startsWith("*") && h.length === 41) return ["mysql41"];
  const map = {
    32: ["md5"],
    40: ["sha1"],
    64: ["sha256"],
    96: ["sha384"],
    128: ["sha512"]
  };
  return map[h.length] || [];
}

crackBtn.addEventListener("click", startCrack);
stopBtn.addEventListener("click", () => {
  stopFlag = true;
  statusEl.textContent = "Stopping…";
});

async function startCrack() {
  if (isRunning) return;

  const raw = hashInput.value.trim();
  if (!raw) return;

  const hashes = raw.split("\n").map(l => l.trim()).filter(Boolean);
  if (hashes.length > 85) {
    alert("Maximum 85 hashes allowed.");
    return;
  }

  isRunning = true;
  stopFlag = false;
  crackBtn.disabled = true;
  stopBtn.disabled = false;
  resultsBody.innerHTML = "";
  progressBar.value = 0;
  statusEl.textContent = "Starting… loading /src/rockyou.txt";

  const targetSet = new Set();
  const needed = new Set();
  const originalMap = {};

  hashes.forEach(h => {
    const lower = h.toLowerCase();
    originalMap[lower] = h;
    targetSet.add(lower);
    detectAlgos(h).forEach(a => needed.add(a));
  });

  const found = {};

  try {
    const response = await fetch("src/rockyou.txt");
    if (!response.ok) throw new Error("Could not load /src/rockyou.txt");

    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buffer = "";
    let bytesRead = 0;
    const contentLength = +response.headers.get("Content-Length") || 0;
    const startTime = performance.now();

    while (true) {
      if (stopFlag) break;

      const { done, value } = await reader.read();
      if (done) break;

      bytesRead += value.length;
      buffer += decoder.decode(value, { stream: true });

      const lines = buffer.split("\n");
      buffer = lines.pop();

      for (const word of lines) {
        if (!word || stopFlag) continue;
        const data = new TextEncoder().encode(word);

        if (needed.has("md5")) {
          const m = md5(word);
          if (targetSet.has(m)) found[m] = ["md5", word];
        }
        if (needed.has("sha1")) {
          const s = await sha1(data);
          if (targetSet.has(s)) found[s] = ["sha1", word];
        }
        if (needed.has("sha256")) {
          const s = await sha256(data);
          if (targetSet.has(s)) found[s] = ["sha256", word];
        }
        if (needed.has("sha384")) {
          const s = await sha384(data);
          if (targetSet.has(s)) found[s] = ["sha384", word];
        }
        if (needed.has("sha512")) {
          const s = await sha512(data);
          if (targetSet.has(s)) found[s] = ["sha512", word];
        }
      }

      const elapsed = (performance.now() - startTime) / 1000;
      const speed = (bytesRead / 1024 / 1024) / Math.max(elapsed, 0.1);
      const pct = contentLength ? Math.min(99, (bytesRead / contentLength) * 100) : 0;

      progressBar.value = pct;
      statusEl.textContent = `Scanning… ${(bytesRead/1024/1024).toFixed(1)} MB  |  ${speed.toFixed(1)} MB/s`;

      if (Object.keys(found).length >= targetSet.size) {
        stopFlag = true;
        break;
      }

      await new Promise(r => setTimeout(r, 0));
    }

  } catch (err) {
    statusEl.textContent = "Error: " + err.message;
    console.error(err);
  }

  hashes.forEach(original => {
    const lower = original.toLowerCase();
    const row = document.createElement("tr");

    if (found[lower]) {
      const [algo, plain] = found[lower];
      row.innerHTML = `
        <td class="exact">${original}</td>
        <td class="exact">${algo.toUpperCase()}</td>
        <td class="exact">${plain}</td>
        <td>●</td>
      `;
    } else {
      row.innerHTML = `
        <td class="notfound">${original}</td>
        <td class="notfound">—</td>
        <td class="notfound">Not found</td>
        <td>●</td>
      `;
    }
    resultsBody.appendChild(row);
  });

  progressBar.value = 100;
  statusEl.textContent = stopFlag ? "Stopped" : "Finished";
  isRunning = false;
  crackBtn.disabled = false;
  stopBtn.disabled = true;
}
