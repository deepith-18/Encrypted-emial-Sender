# 🔒 Encrypted Email Sender

A secure, web-based email application that provides end-to-end encryption for confidential communication using a hybrid RSA and AES encryption scheme. This project ensures that messages are unreadable by anyone except the intended recipient, including the email service provider.

 <!-- Optional: Add a screenshot URL -->

## ✨ Key Features

-   **End-to-End Encryption**: Messages are encrypted in the browser and decrypted only by the recipient.
-   **Hybrid Encryption Scheme**: Combines the speed of **AES-256** for message encryption with the security of **RSA-2048** for key exchange.
-   **Digital Signatures**: Ensures message integrity and authenticates the sender using RSA-PSS.
-   **Secure Key Management**: User private keys are encrypted with a password-derived key (PBKDF2) and are never stored in plaintext.
-   **Modern Web Interface**: A clean, responsive, and interactive user interface built with Flask and Bootstrap.
-   **Interactive Sending**: Emails are sent in the background (AJAX) with animated loading indicators and success/error pop-ups.

## 🛠️ Technology Stack

-   **Backend**: Python 3.8+, Flask
-   **Cryptography**: PyCryptodome (for AES, RSA, PBKDF2, SHA-256)
-   **Database**: SQLite
-   **Email Protocols**: `smtplib` for sending emails via SMTP.
-   **Frontend**: HTML5, Bootstrap 5 (Bootswatch Cyborg Theme), JavaScript, jQuery, AOS (Animate on Scroll), SweetAlert2

## 🚀 Getting Started

Follow these instructions to get a copy of the project up and running on your local machine for development and testing purposes.

### 1. Prerequisites

-   Python 3.8 or higher
-   `pip` (Python package installer)

### 2. Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/encrypted-email-sender.git
    cd encrypted-email-sender
    ```

2.  **Create and activate a virtual environment:**

    -   **Windows (PowerShell):**
        ```powershell
        python -m venv venv
        .\venv\Scripts\activate
        ```
    -   **macOS / Linux:**
        ```bash
        python3 -m venv venv
        source venv/bin/activate
        ```

3.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

### 3. Configuration

This application requires a Gmail account to send emails.

1.  **Enable 2-Factor Authentication** on your Google Account.
2.  **Generate a Google App Password**. This is a special 16-character password that gives an app permission to access your Google Account.
    -   Go to your [Google Account Security Page](https://myaccount.google.com/security).
    -   Click on **App passwords**.
    -   Select "Mail" for the app and "Other (Custom name)" for the device. Name it `Flask Secure Mail`.
    -   Copy the generated 16-character password.

3.  **Create a `.env` file** in the root directory of the project. You can copy the `.env.example` if it exists, or create a new file.

4.  **Edit the `.env` file** with your credentials:
    ```ini
    # .env
    SMTP_SERVER='smtp.gmail.com'
    SMTP_PORT=587
    SMTP_USER='your-email@gmail.com'
    SMTP_PASSWORD='your-16-character-app-password'
    ```

### 4. Initialize the Database

Run the following command in your terminal to create the database and its tables:
```bash
python -c "from database.db_manager import init_db; init_db()"
```
This will create an `app.db` file in the `database/` directory.

### 5. Run the Application

Start the Flask development server:
```bash
flask --app app run
```
The application will be available at `http://127.0.0.1:5000`.

## 📖 How to Use

The core principle is that **both the sender and the recipient must be registered users** of this application, as it needs their public keys to perform encryption and signature verification.

1.  **Register Two Users**: Open the application in your browser and create two separate accounts (e.g., `alice` with `alice@email.com` and `bob` with `bob@email.com`).
2.  **Log in as Alice**: Sign in with Alice's credentials.
3.  **Compose an Email**:
    -   Navigate to the **Compose** page.
    -   Enter Bob's email (`bob@email.com`) as the recipient.
    -   Write a subject and a secret message.
    -   Click "Encrypt and Send". You will see an interactive pop-up.
4.  **Check Bob's Real Inbox**:
    -   Log in to Bob's actual email account (e.g., Gmail).
    -   He will have a new email with the subject `[ENCRYPTED]...`. The body will contain a block of unreadable, encrypted text.
5.  **Decrypt the Message**:
    -   Log out of Alice's account in the application and **log in as Bob**.
    -   Navigate to the **Decrypt** page.
    -   Copy the entire encrypted message body from Bob's email.
    -   Paste it into the "Encrypted Message" text area.
    -   Enter the sender's email (`alice@email.com`) to allow the app to find her public key for signature verification.
    -   Click "Decrypt Message". The original secret message will be revealed.

## 🔐 How the Encryption Works

This application uses a **Hybrid Encryption Scheme** to combine the best of symmetric and asymmetric cryptography.

1.  **Generate a random, one-time AES-256 key** (session key).
2.  **Encrypt the main message** using this fast AES session key.
3.  **Encrypt the AES session key** using the recipient's slow but secure **RSA public key**.
4.  **Create a digital signature** by hashing the original message (SHA-256) and encrypting the hash with the **sender's RSA private key**.
5.  The final email contains the encrypted message, the encrypted session key, and the digital signature. Only the recipient can use their private key to unlock the session key and, in turn, unlock the message.

## 📄 License

This project is licensed under the MIT License.
