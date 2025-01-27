<h1>Password Manager</h1>

<p>This Password Manager is a secure and user-friendly application designed to help users safely store, manage, and retrieve their login credentials. Built using Python and its various libraries, this tool provides an intuitive interface and strong encryption to keep your sensitive information secure.</p>

<p>The application allows you to:</p>
<ul>
    <li>Store and retrieve usernames and passwords for various websites.</li>
    <li>Encrypt passwords using AES encryption for safety.</li>
    <li>Copy passwords directly to the clipboard.</li>
    <li>Add, update, or delete entries from your password vault.</li>
    <li>Ensure passwords are securely hidden using a toggle feature.</li>
</ul>

<h2>Features:</h2>
<ul>
    <li><strong>Password Storage</strong>: Securely save and retrieve login details for websites.</li>
    <li><strong>Encryption</strong>: Use AES encryption and a master key for securing your data.</li>
    <li><strong>Copy to Clipboard</strong>: Easily copy your password with a single click.</li>
    <li><strong>Vault Management</strong>: Add, update, or delete entries in your password vault.</li>
    <li><strong>User-friendly Interface</strong>: Simple and clean GUI for an excellent user experience.</li>
</ul>

<h2>Tech Stack</h2>
<ul>
    <li><strong>Python</strong>: The core programming language used to build this application.</li>
    <li><strong>tkinter</strong>: For building the graphical user interface (GUI) of the application.</li>
    <li><strong>pyperclip</strong>: For enabling the copy-paste functionality, allowing users to copy passwords to their clipboard.</li>
    <li><strong>cryptography</strong>: For implementing encryption and decryption using the Fernet symmetric encryption method and PBKDF2 for password-based key derivation.</li>
    <li><strong>sqlite3</strong>: For database management, storing passwords securely within a local SQLite database.</li>
</ul>

<h2>How to Use</h2>
<ol>
    <li><strong>Set Up</strong>:<br>
        - Download and install Python 3.x from <a href="https://www.python.org/">python.org</a>.<br>
        - Install the necessary libraries:<br>
        <code>pip install pyperclip cryptography</code><br>
        - Note when packaging the project into an exe be sure to run <code>pyinstaller --onefile --add-data "requirements/images/lock.ico;requirements/images" --add-data "requirements/images/fingerprint.ico;requirements/images" --add-data "requirements/images/unlock.ico;requirements/images" --noconsole main.py</code>
    </li>
    <li><strong>Running the App</strong>:<br>
        - Run the application by executing <code>password_manager.py</code> in your terminal or command prompt.<br>
        - On the first run, you will be prompted to create a master password. This will be used to encrypt and decrypt your password vault.
    </li>
    <li><strong>Using the Vault</strong>:<br>
        - <strong>Add Password</strong>: Click the "Add Password" button to add a new website, username, and password.<br>
        - <strong>Toggle Password</strong>: Hide or show a password by clicking the "Show" button next to it.<br>
        - <strong>Copy Password</strong>: Use the "Copy" button to copy the password to your clipboard for easy pasting.<br>
        - <strong>Update Password</strong>: Update a stored password by clicking the "Update" button.<br>
        - <strong>Delete Entry</strong>: Remove any password entry from the vault using the "Delete" button.
    </li>
</ol>

<h2>Security</h2>
<p>The application uses a strong encryption method (AES) to protect your passwords. Your passwords are encrypted with a master password, which is never stored. The vault is encrypted using a key derived from your master password using PBKDF2, and passwords are encrypted with the Fernet symmetric encryption system.</p>

<h2>License</h2>
<p>This project is open-source and free to use under the MIT license.</p>
