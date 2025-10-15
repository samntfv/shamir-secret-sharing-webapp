# 🔐 Shamir Secret Sharing Web App

A modern, privacy-focused web app that lets you **encrypt sensitive text or files** using **AES-256-GCM** and securely **distribute the encryption key** among trusted parties using **Shamir’s Secret Sharing**.\
Everything runs **entirely in your browser** — no data is uploaded or stored anywhere.

**Live version**: [here](https://precious-cassata-cd874d.netlify.app/)

---

## ✨ Features

- 🧩 **Shamir’s Secret Sharing**\
  Split the AES key into *N* shares.\
  Choose a threshold *T* (minimum shares required for recovery).

- 🔒 **AES-256 Encryption**\
  Encrypt text or any file client-side.\
  Uses browser-native WebCrypto API — no dependencies, no servers.

- 📁 **Text & File Support**\
  Encrypt plain text or upload a file (up to 50 MB by default).\
  Automatically restores the original file type when decrypted.

- ☁️ **Easy Envelope Sharing**\
  The encrypted envelope (JSON file) can safely be hosted on **file-sharing services** or cloud storage.\
  Only those with the required number of valid shares can decrypt the contents.\
  This helps reduce bandwidth use when sharing large encrypted files.

- 🧠 **Zero Backend**\
  100% offline — all cryptographic operations occur locally.\
  No data leaves your browser.

- 🧰 **Security by Design**\
  Content Security Policy (CSP) compliant — no inline scripts or styles.\
  Uses `window.crypto.getRandomValues()` for strong randomness.\
  Compatible with HTTPS static hosting.

- 🪄 **Clean, Modern UI**\
  Responsive glass-style design with progress bars and toast notifications.\
  Works on both desktop and mobile.

---

## 🚀 Getting Started

### 1. Clone or Download

```
git clone https://github.com/<your-username>/shamir-secret-sharing-webapp.git
cd shamir-secret-sharing-webapp
```

### 2. Open in Browser

Simply open `index.html` in a modern browser (Chrome, Edge, Firefox, Safari).\
No build process or server is required.

---

## 🧩 How It Works

1. **Create Shares**

   - Enter or upload a secret (text or file).
   - Choose the number of shares and threshold.
   - Download the resulting **shares** and the **encrypted envelope**.

2. **Recover Secret**

   - Upload the envelope JSON.
   - Upload enough share files (meeting the threshold).
   - The AES key is reconstructed and the data decrypted — locally.

---

## 🧠 Security Notes

- All encryption, decryption, and key splitting happen in your browser.
- For maximum privacy:
  - Use this tool on **trusted devices only**.
  - Open it in a **private/incognito window**.
  - **Disable browser extensions** that could access the DOM.
- You can safely store or share the envelope file publicly — it’s encrypted and useless without the threshold number of valid shares.
- No guarantees or warranties are provided; use at your own risk.

---

## ☕ Support the Project

If you find this tool useful, you can support development here: <a href="https://www.buymeacoffee.com/smnfv" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>



---

## 📜 License

MIT License © 2025 [Samuel Perrone](https://buymeacoffee.com/smnfv)

---

### 🏷️ Repository Info

**Name:** `shamir-secret-sharing-webapp`\
**Description:**

> Secure, client-side AES-256 encryption with Shamir’s Secret Sharing. Split and recover secrets entirely offline — privacy-first and open-source.

**Tags:**\
`encryption`, `crypto`, `webcrypto`, `AES`, `Shamir`, `secret-sharing`, `offline`, `privacy`, `client-side`, `security`

