This Chrome extension provides AES encryption/decryption and RSA signing/verification capabilities, along with RSA encryption/decryption, allowing users to easily handle file security operations in the browser. The following is a detailed introduction to the functions and application environment:

### Introduction to extended functions

#### 1. **AES Encryption and Decryption**
 - **Function Description**: Using the AES-GCM algorithm, users can encrypt files into ciphertext files, or decrypt encrypted files back to original files. AES-GCM is an advanced encryption mode with efficient encryption performance and data integrity guarantee.
 - **How to Use**:
   - The user selects a file and a set of keys, which are hashed and an AES key is generated.
   - Encrypt or decrypt via button operations and automatically download the encrypted or decrypted files.
 - **Application Example**:
   - Protect the privacy of local files, such as encrypting private files before transmitting them over the network.
   - Decrypt the received ciphertext and view the original file content.

#### 2. **RSA Signature and Verification**
 - **Function Description**: Users can use RSA keys to digitally sign files or verify the digital signature of files. Digital signatures guarantee document integrity and authenticity of origin.
 - **How to Use**:
   - Users can generate a set of RSA key pairs (public key and private key) and download them. The RSA key generated in the program is 2048 bits.
   - Signature: Select the private key and file to generate a digital signature for the file.
   - Verification: Select the public key, original file, and signature file for signature verification.
 - **Application Example**:
   - Verify the source of the file to ensure it has not been modified.
   - Generate signature files to ensure the authenticity and reliability of files during transmission.

#### 3. **RSA Encryption and Decryption**
 - **Function Description**: Users can encrypt files using RSA public keys or decrypt files with corresponding RSA private keys. This feature is useful for secure data sharing.
 - **How to Use**:
   - Encryption: Select a file and an RSA public key to encrypt the content. Note that RSA is best suited for small files or encryption of symmetric keys due to its size limitations.
   - Decryption: Use the RSA private key that corresponds to the encryption public key to decrypt the file.
 - **Application Example**:
   - Encrypt sensitive information before sharing it with others, ensuring that only the intended recipient with the correct private key can access the content.
   - Decrypt received files encrypted with your public key to view the original information.

### Application Environment

This extension works for the Chrome browser and requires the `chrome.downloads` API to be enabled to handle file downloads. Application environments include:

- **Operating System**: Windows, MacOS, Linux are all acceptable, as long as the Chrome browser is installed.
- **Application Scenarios**:
   - **Enterprises or Organizations**: Suitable for enterprises that require simple file encryption, digital signatures, and secure file sharing.
   - **Personal Use**: Protection of personal privacy files, such as encrypting personal data for storage or transmission.
   - **Developers and Technicians**: As a tool for learning and testing encryption technology, it is convenient to understand the basic operations of AES and RSA.

### Technical Details

- **AES-GCM Mode**: Uses symmetric key encryption, which has high security and is suitable for large file encryption.
- **RSA-PSS Mode**: Used for digital signature verification, with a 2048-bit modulus to ensure the strength of the signature.
- **RSA-OAEP Mode**: Used for RSA encryption and decryption. RSA-OAEP with a 2048-bit key is suitable for securely encrypting small data, such as AES keys or other small sensitive files.
- **Browser API**: Utilizes `crypto.subtle` and `chrome.downloads` APIs to simplify encryption, decryption, and signing, and supports automatic file downloading.

---------------------------------------------------------------------------------

這個 Chrome 擴充應用程式提供了 AES 加密/解密、RSA 簽章/驗證以及 RSA 加密/解密功能，能讓使用者在瀏覽器中輕鬆處理檔案加密、簽章與解密操作。以下是功能和應用環境的詳細介紹：

### 擴充功能介紹

#### 1. **AES 加密與解密**
   - **功能描述**：透過 AES-GCM 演算法，使用者可以將文件加密成密文檔案，或將已加密的檔案解密回原始文件。AES-GCM 是一種先進的加密模式，具備高效的加密性能及數據完整性保證。
   - **使用方式**：
      - 使用者選擇一個檔案和一組金鑰（Key），該金鑰會進行哈希處理並生成 AES 金鑰。
      - 透過按鈕操作來加密或解密，並自動下載加密或解密後的檔案。
   - **應用範例**：
      - 保障本地文件的隱私，例如加密私密文件後再透過網路傳輸。
      - 解密收到的密文，查看原始文件內容。

#### 2. **RSA 簽章與驗證**
   - **功能描述**：使用者可以利用 RSA 金鑰對文件進行數位簽章，或驗證文件的數位簽章。數位簽章能保證文件的完整性和來源的真實性。
   - **使用方式**：
      - 使用者可生成一組 RSA 金鑰對（公鑰與私鑰）並下載。程式中生成的 RSA 金鑰是 2048 位元。
      - 簽章：選擇私鑰和檔案，生成文件的數位簽章。
      - 驗證：選擇公鑰、原始檔案和簽章檔案來進行簽章驗證。
   - **應用範例**：
      - 驗證文件來源，確保未經修改。
      - 生成簽章檔案，確保文件在傳輸過程中的真實性與可靠性。

#### 3. **RSA 加密與解密**
   - **功能描述**：使用 RSA 公鑰加密文件或用對應的 RSA 私鑰解密文件，適用於保密性文件傳輸。
   - **使用方式**：
      - 加密：選擇檔案和 RSA 公鑰加密內容。由於 RSA 加密大小限制，建議用於小型文件或 AES 金鑰的加密。
      - 解密：使用對應的私鑰解密 RSA 加密的檔案。
   - **應用範例**：
      - 加密敏感資訊後與他人分享，確保只有擁有相應私鑰的接收者可以讀取。
      - 解密收到的加密文件，以查看原始內容。

### 應用環境

這個擴充應用程式適用於 Chrome 瀏覽器，並需要啟用 `chrome.downloads` API 來處理文件的下載。應用環境包括：

- **操作系統**：Windows、MacOS、Linux 皆可，只要裝有 Chrome 瀏覽器。
- **應用場景**：
   - **企業或組織**：適用於需要簡易檔案加密、數位簽章和保密文件分享的企業，能保障機密文件的安全性。
   - **個人用戶**：個人隱私文件的保護，例如將個人資料加密後儲存或傳輸。
   - **開發者與技術人員**：作為學習和測試加密技術的工具，方便了解 AES 和 RSA 的基礎操作。

### 技術細節

- **AES-GCM 模式**：使用對稱金鑰加密，安全性較高，適合大文件加密。
- **RSA-PSS 模式**：適用於數位簽章驗證，2048 位元模數確保簽章強度。
- **RSA-OAEP 模式**：適用於 RSA 加密與解密。2048 位元 RSA-OAEP 適用於加密小型數據，例如 AES 金鑰或其他小型敏感文件。
- **瀏覽器 API**：利用 `crypto.subtle` 和 `chrome.downloads` API，簡化加密、解密和簽章處理，並支援文件自動下載。