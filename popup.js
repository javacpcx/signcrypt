document.addEventListener("DOMContentLoaded", () => {
    // 檢查元素是否存在
    const rsaFileInput = document.getElementById("rsaFileInput");
    const keyFileInput = document.getElementById("keyFileInput");
    const sigFileInput = document.getElementById("sigFileInput");

    // 檢查 RSA 元素是否存在
    const rsaEncryptFileInput = document.getElementById("rsaEncryptFileInput");
    const rsaEncryptKeyInput = document.getElementById("rsaEncryptKeyInput");
    const rsaEncryptOperation = document.getElementById("rsaEncryptOperation");

    console.log("rsaFileInput:", rsaFileInput);
    console.log("keyFileInput:", keyFileInput);
    console.log("sigFileInput:", sigFileInput);

    // 確認元素是否為 null
    if (!rsaFileInput || !keyFileInput || !sigFileInput) {
        console.error("One or more required file inputs are missing.");
        return;
    }

    // === AES 加密解密 ===

    // 生成 AES 金鑰
    async function generateAESKey(keyData) {
        try {
            const enc = new TextEncoder();
            const hash = await crypto.subtle.digest("SHA-256", enc.encode(keyData));
            return await crypto.subtle.importKey("raw", hash, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
        } catch (error) {
            console.error("Error generating AES key:", error);
            throw error;
        }
    }

    // AES 加密
    async function aesEncrypt(key, data) {
        try {
            const iv = crypto.getRandomValues(new Uint8Array(12)); // 隨機生成 IV
            const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
            return { iv, encrypted };
        } catch (error) {
            console.error("Error during AES encryption:", error);
            throw error;
        }
    }

    // AES 解密
    async function aesDecrypt(key, iv, data) {
        try {
            return await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
        } catch (error) {
            console.error("Error during AES decryption:", error);
            throw error;
        }
    }

    // 綁定 AES 加密按鈕
    document.getElementById("aesEncryptBtn").addEventListener("click", async () => {
        try {
            const fileInput = document.getElementById("aesFileInput");
            const keyString = document.getElementById("aesKey").value;

            if (!fileInput.files.length || !keyString) {
                alert("Please select a file and enter an AES key.");
                return;
            }

            const file = fileInput.files[0];
            const key = await generateAESKey(keyString);
            const reader = new FileReader();

            reader.onload = async () => {
                const fileData = new Uint8Array(reader.result);
                const { iv, encrypted } = await aesEncrypt(key, fileData);

                const blob = new Blob([iv, new Uint8Array(encrypted)], { type: "application/octet-stream" });
                const url = URL.createObjectURL(blob);
                chrome.downloads.download({ url, filename: `${file.name}.enc`, saveAs: true });
            };

            reader.readAsArrayBuffer(file);
        } catch (error) {
            console.error("Error in AES encryption button:", error);
        }
    });

    // 綁定 AES 解密按鈕
    document.getElementById("aesDecryptBtn").addEventListener("click", async () => {
        try {
            const fileInput = document.getElementById("aesFileInput");
            const keyString = document.getElementById("aesKey").value;

            if (!fileInput.files.length || !keyString) {
                alert("Please select an encrypted file and enter an AES key.");
                return;
            }

            const file = fileInput.files[0];
            const key = await generateAESKey(keyString);
            const reader = new FileReader();

            reader.onload = async () => {
                const fileData = new Uint8Array(reader.result);
                const iv = fileData.slice(0, 12); // 提取前 12 個位元組作為 IV
                const encryptedData = fileData.slice(12);

                try {
                    const decrypted = await aesDecrypt(key, iv, encryptedData);
                    const blob = new Blob([decrypted], { type: "application/octet-stream" });
                    const url = URL.createObjectURL(blob);
                    chrome.downloads.download({ url, filename: file.name.replace(".enc", "_decrypted"), saveAs: true });
                } catch (e) {
                    console.error("Error in AES decryption:", e);
                    alert("Decryption failed: " + e.message);
                }
            };

            reader.readAsArrayBuffer(file);
        } catch (error) {
            console.error("Error in AES decryption button:", error);
        }
    });

    // === RSA 金鑰生成、簽章與驗證 ===

    // 生成 RSA 金鑰對
    async function generateRSAKeyPair() {
        try {
            const keyPair = await crypto.subtle.generateKey(
                { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
                true,
                ["sign", "verify"]
            );

            const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
            const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);

            downloadKey("privateKey.key", privateKey);
            downloadKey("publicKey.key", publicKey);
            document.getElementById("keyStatus").textContent = "RSA Key Pair Generated!";
        } catch (error) {
            console.error("Error generating RSA key pair:", error);
        }
    }

    // 下載金鑰檔案
    function downloadKey(filename, keyData) {
        const blob = new Blob([keyData], { type: "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        chrome.downloads.download({ url, filename, saveAs: true });
    }

    // RSA 簽章
    async function rsaSign(privateKeyData, data) {
        try {
            const privateKey = await crypto.subtle.importKey("pkcs8", privateKeyData, { name: "RSA-PSS", hash: "SHA-256" }, false, ["sign"]);
            const signature = await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, privateKey, data);
            return signature;
        } catch (error) {
            console.error("Error during RSA signing:", error);
            throw error;
        }
    }

    // RSA 驗證
    async function rsaVerify(publicKeyData, signature, data) {
        try {
            const publicKey = await crypto.subtle.importKey("spki", publicKeyData, { name: "RSA-PSS", hash: "SHA-256" }, false, ["verify"]);
            return await crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, publicKey, signature, data);
        } catch (error) {
            console.error("Error during RSA verification:", error);
            throw error;
        }
    }

    // 綁定 RSA 金鑰生成按鈕
    document.getElementById("generateKeyPairBtn").addEventListener("click", generateRSAKeyPair);

    // 綁定 RSA 簽章和驗證按鈕
    document.getElementById("rsaProcessBtn").addEventListener("click", async () => {
        try {
            const rsaOperation = document.getElementById("rsaOperation").value;
            const file = rsaFileInput.files[0];
            const keyFile = keyFileInput.files[0];

            if (rsaOperation === "sign" && (!file || !keyFile)) {
                alert("Please select the original file and private key file for signing.");
                return;
            }

            if (rsaOperation === "verify" && (!file || !keyFile || !sigFileInput.files[0])) {
                alert("Please select the original file, signature file, and public key file for verification.");
                return;
            }

            const fileReader = new FileReader();
            const keyReader = new FileReader();

            if (rsaOperation === "sign") {
                keyReader.onload = async () => {
                    const privateKeyData = new Uint8Array(keyReader.result);
                    fileReader.onload = async () => {
                        const fileData = new Uint8Array(fileReader.result);
                        try {
                            const signature = await rsaSign(privateKeyData, fileData);

                            const blob = new Blob([new Uint8Array(signature)], { type: "application/octet-stream" });
                            const url = URL.createObjectURL(blob);
                            chrome.downloads.download({ url, filename: `${file.name}.sig`, saveAs: true });
                            alert("Signature created and downloaded.");
                        } catch (error) {
                            console.error("Error during RSA signing:", error);
                            alert("Signing failed.");
                        }
                    };
                    fileReader.readAsArrayBuffer(file);
                };
                keyReader.readAsArrayBuffer(keyFile);
            }

            if (rsaOperation === "verify") {
                const sigReader = new FileReader();

                keyReader.onload = async () => {
                    const publicKeyData = new Uint8Array(keyReader.result);

                    sigReader.onload = async () => {
                        const signature = new Uint8Array(sigReader.result);
                        fileReader.onload = async () => {
                            const fileData = new Uint8Array(fileReader.result);
                            try {
                                const isValid = await rsaVerify(publicKeyData, signature, fileData);
                                alert(`Signature valid: ${isValid}`);
                            } catch (error) {
                                console.error("Error during RSA signature verification:", error);
                                alert("Signature verification failed.");
                            }
                        };
                        fileReader.readAsArrayBuffer(file);
                    };
                    sigReader.readAsArrayBuffer(sigFileInput.files[0]);
                };
                keyReader.readAsArrayBuffer(keyFile);
            }
        } catch (error) {
            console.error("Error in RSA processing button:", error);
        }
    });

    // === RSA 加密與解密 ===

    // RSA 公鑰加密
    async function rsaEncrypt(publicKeyData, data) {
        try {
            const publicKey = await crypto.subtle.importKey(
                "spki",
                publicKeyData,
                { name: "RSA-OAEP", hash: "SHA-256" },
                false,
                ["encrypt"]
            );
            return await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, data);
        } catch (error) {
            console.error("Error during RSA encryption:", error);
            alert("Encryption failed, please check whether the Public Key is correct.");
            throw error;
        }
    }

    // RSA 私鑰解密
    async function rsaDecrypt(privateKeyData, data) {
        try {
            const privateKey = await crypto.subtle.importKey(
                "pkcs8",
                privateKeyData,
                { name: "RSA-OAEP", hash: "SHA-256" },
                false,
                ["decrypt"]
            );
            return await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, data);
        } catch (error) {
            console.error("Error during RSA decryption:", error);
            alert("Decryption failed, please check whether the Secret Key is correct.");
            throw error;
        }
    }

    // 綁定 RSA 加密解密按鈕
    document.getElementById("rsaEncryptProcessBtn").addEventListener("click", async () => {
        try {
            const operation = rsaEncryptOperation.value;
            const file = rsaEncryptFileInput.files[0];
            const keyFile = rsaEncryptKeyInput.files[0];

            if (!file || !keyFile) {
                alert("Please select the file and key file to process.");
                return;
            }

            const fileReader = new FileReader();
            const keyReader = new FileReader();

            keyReader.onload = async () => {
                const keyData = new Uint8Array(keyReader.result);

                fileReader.onload = async () => {
                    const fileData = new Uint8Array(fileReader.result);

                    try {
                        let result;
                        if (operation === "encrypt") {
                            if (fileData.length > 190) {
                                alert("The file is too large, RSA is only suitable for small file encryption. It is recommended to use AES encryption and then RSA to encrypt the AES key.");
                                return;
                            }
                            result = await rsaEncrypt(keyData, fileData);
                        } else if (operation === "decrypt") {
                            result = await rsaDecrypt(keyData, fileData);
                        }

                        const blob = new Blob([new Uint8Array(result)], { type: "application/octet-stream" });
                        const url = URL.createObjectURL(blob);
                        const extension = operation === "encrypt" ? ".encrypted" : ".decrypted";
                        chrome.downloads.download({ url, filename: file.name + extension, saveAs: true });
                        alert(`${operation === "encrypt" ? "Encrypt加密" : "Decrypt解密"}finished and download.`);
                    } catch (error) {
                        console.error(`Error during RSA ${operation}:`, error);
                        alert(`${operation === "encrypt" ? "Encrypt加密" : "Decrypte解密"}fail.`);
                    }
                };

                fileReader.readAsArrayBuffer(file);
            };

            keyReader.readAsArrayBuffer(keyFile);
        } catch (error) {
            console.error("Error in RSA encrypt/decrypt process button:", error);
        }
    });
});