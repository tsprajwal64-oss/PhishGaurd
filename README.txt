PHISHGUARD PROFESSIONAL UI UPGRADE

Replace the matching files in your existing project:
- public/index.html
- public/phishing.css
- public/phishing.js
- src/PhishGuardServer.java

No login, registration, database, Node.js, or external Java libraries are required.
Java 11 or newer is required.

Run in VS Code PowerShell from the PhishGuard_v2 project root:
  javac -d out src/PhishGuardServer.java
  java -cp out PhishGuardServer

Open:
  http://localhost:8081

Features retained:
- Paste-email analysis
- RDAP sender-domain investigation
- Screenshot OCR using Tesseract.js CDN
- Last 10 records in browser localStorage
- Threat trend chart
- Light/dark theme

New UI:
- Animated circular risk percentage
- Smooth risk colour bands
- Risk-adaptive page background
- Animated result panel
- Responsive layout

Important:
This is a rules-based educational detector, not a production anti-phishing service.
A low/zero score does not prove an email is safe. Sender RDAP lookup does not authenticate
the sender. OCR requires internet access to load the Tesseract.js library.
