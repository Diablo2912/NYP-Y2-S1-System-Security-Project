# NYP Y2 S1 System Security Project IT2656

The objective of this project is for students to apply the knowledge and skills acquired to demonstrate insecure and secure web applications/APIs/Systems and develop secure web applications, including systems.

#### Project Description
Cropzy is an all in one platform which aims to equip farmers with the resources and tools to optimize productivity/crop yield while prioritizing sustainability.

Features: 
- Sustainable Eco-Friendly Agricultural Products on sale
- Tools such as Carbon Footprint Tracker, Crop Calendar, Seasonal Updates
- Resources such as news articles, educational videos, related information like soil information, Chatbot

#### Note

Some features may not work as intended as sensitive values (API keys, secret keys, database credentials) have been removed for security reasons.

To run the project locally, you will need to:

- Set up your own `.env` file with the required environment variables (see `.env` for reference).
- Provide your own API keys/secrets (e.g., Google, Twilio, Stripe, reCAPTCHA).

## Python Version
Python 3.11.0

## Install Required Dependencies

```bash
  pip install -r requirements.txt
```

## MySQL Database Scripts
Configure your own MySQL Database connection

[DB Scripts]([https://linktodocumentation](https://github.com/Diablo2912/NYP-Y2-S1-System-Security-Project/blob/master/db_script.sql)

## Group Members

- Brandon Ngiam Wen Kai (Team Lead)
- Loo Yong Hong Glen (DB Admin)
- Dhanasekaran Sachin (UI Admin)
- Sadev Dulneth

## Features Done by Each Member

### Brandon Ngiam Wen Kai
- Rate Limiting
- Password Reset
- Account Freeze
- Secure Chatbot Input
- Account Creation Check

### Dhanasekaran Sachin
- Session Management
- Email Notifications (under Session Management)
- Security Challenges & Re-authentication
- Error Handling
- Input Validation

### Loo Yong Hong Glen
- Authentication Token
- Multi-Factor Authentication
- Logs
- IP Management
- Geofencing
- Role-Based Access Control
- Input Sanitisation

### Sadev Dulneth
- CSRF Protection
- Auto Form Destruct Timer
- Encrypted Recovery Code
- Secure Header and HTTPS
- Security Checkup Page
- Clickjacking Prevention
- Google OAuth
