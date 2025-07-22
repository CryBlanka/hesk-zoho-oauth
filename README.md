# Zoho OAuth2 Login Integration for HESK

This script (`zoho_auth.php`) enables admin login to HESK using Zoho OAuth2, replacing traditional password login with secure OAuth authentication.

<span style="color:red">If you wish to contribute and add support for more OAuth providers, feel free to base off the original script and push new providers into this directory.</span>

---

## Features

- Zoho OAuth2 login flow for HESK admins  
- Matches Zoho email with existing HESK user  
- Sets up secure session, bypassing password and MFA  
- Stores Zoho access and refresh tokens in session  

---

## Setup

1. Configure your Zoho OAuth2 credentials inside the `ZohoAuth` class (`clientId`, `clientSecret`, `redirectUri`, `scope`).  
2. Place `zoho_auth.php` in your HESK admin folder.  

---

## Integrate with HESK Admin UI

### Adding Zoho Login to `admin/index.php`

Add this **outside** (above or below) the traditional login form:

```html
<div class="form__submit" style="margin-top: 20px;">
    <a href="zoho_auth.php?action=login" class="btn btn-full" style="text-decoration: none; display: block; text-align: center;">
        Login with Zoho
    </a>
</div>

```

## Adding Zoho OAuth to `elevator.php`

Add this code at the top of `elevator.php`:

```php
if (hesk_GET('oauth') === 'zoho') {
    $_SESSION['elevator_target'] = hesk_SESSION('elevator_target', 'admin_main.php');
    $_SESSION['oauth_elevator_mode'] = true;
    header('Location: zoho_auth.php?action=login');
    exit();
}

if (isset($_SESSION['oauth_elevator_mode']) && isset($_SESSION['oauth_authenticated'])) {
    unset($_SESSION['oauth_elevator_mode']);
    unset($_SESSION['oauth_authenticated']);
    handle_successful_elevation();
}

```
Use the URL elevator.php?oauth=zoho to trigger Zoho OAuth elevation.

---

## Requirements
- PHP with cURL enabled
- HESK version 3.6 or higher (was developed on HESK 3.6.2, feel free to push changes if broken)
- Registered Zoho OAuth2 application
- Only users with matching emails in HESK can log in via Zoho OAuth.
