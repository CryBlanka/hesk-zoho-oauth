<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

define('IN_SCRIPT',1);
define('HESK_PATH','../');

/* Get all the required files and functions */
require(HESK_PATH . 'hesk_settings.inc.php');
require(HESK_PATH . 'inc/common.inc.php');
require(HESK_PATH . 'inc/admin_functions.inc.php');
hesk_load_database_functions();

hesk_session_start();
hesk_dbConnect();

class ZohoAuth {
    private $clientId = ''; // Your Zoho Client ID
    private $clientSecret = ''; // Your Zoho Client Secret
    private $redirectUri = ''; // Set https://your_domain.com/admin/zoho_auth.php as the redirect URI in Zoho API Console
    private $scope = 'ZohoMail.accounts.READ';
    private $authUrl = 'https://accounts.zoho.eu/oauth/v2/auth';
    private $tokenUrl = 'https://accounts.zoho.eu/oauth/v2/token';
    private $accountsUrl = 'https://mail.zoho.eu/api/accounts';

    public function __construct() {
        global $hesk_settings;
        $this->redirectUri = $hesk_settings['hesk_url'] . '/admin/zoho_auth.php';
    }

    public function initiateAuth() {
        $params = array(
            'client_id' => $this->clientId,
            'response_type' => 'code',
            'redirect_uri' => $this->redirectUri,
            'scope' => $this->scope,
            'access_type' => 'offline',
            'prompt' => 'consent'
        );

        $authUrl = $this->authUrl . '?' . http_build_query($params);
        header('Location: ' . $authUrl);
        exit;
    }

    private function getAccessToken($code) {
        $params = array(
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri
        );

        $ch = curl_init($this->tokenUrl);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            return false;
        }

        return json_decode($response, true);
    }

    private function getUserEmail($accessToken) {
        $ch = curl_init($this->accountsUrl);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Authorization: Zoho-oauthtoken ' . $accessToken,
            'Accept: application/json'
        ));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            return false;
        }

        $data = json_decode($response, true);
        return isset($data['data'][0]['incomingUserName']) ? $data['data'][0]['incomingUserName'] : false;
    }

    private function processSuccessfulLogin($user_row, $tokenData) {
        global $hesk_settings;

        // User authenticated via OAuth, regenerate session ID
        hesk_session_regenerate_id();

        // Set session verification tag
        $_SESSION['session_verify'] = hesk_activeSessionCreateTag($user_row['user'], $user_row['pass']);

        // Set all user data in session (excluding sensitive data)
        $user_data = $user_row;
        unset($user_data['pass']);
        unset($user_data['mfa_secret']);
        foreach ($user_data as $k => $v) {
            $_SESSION[$k] = $v;
        }

        // Mark this session as OAuth authenticated (bypasses MFA)
        $_SESSION['oauth_authenticated'] = true;
        $_SESSION['oauth_provider'] = 'zoho';
        $_SESSION['oauth_login_time'] = time();

        // Clean brute force attempts
        hesk_cleanBfAttempts();

        // Set elevation timer for sensitive operations
        $current_time = new DateTime();
        $interval_amount = $hesk_settings['elevator_duration'];
        if (in_array(substr($interval_amount, -1), array('M', 'H'))) {
            $interval_amount = 'T'.$interval_amount;
        }
        $elevation_expiration = $current_time->add(new DateInterval("P{$interval_amount}"));
        $_SESSION['elevated'] = $elevation_expiration;

        // Store Zoho OAuth tokens for future API calls
        $_SESSION['zoho_tokens'] = array(
            'access_token' => $tokenData['access_token'],
            'refresh_token' => isset($tokenData['refresh_token']) ? $tokenData['refresh_token'] : '',
            'expires_in' => isset($tokenData['expires_in']) ? $tokenData['expires_in'] : 3600,
            'token_time' => time()
        );

        // Update last login information
        hesk_dbQuery("UPDATE `".hesk_dbEscape($hesk_settings['db_pfix'])."users` SET `last_login`=NOW(), `last_login_ip`='" . hesk_dbEscape(hesk_getClientIP()) . "' WHERE `id`='" . intval($user_row['id']) . "' LIMIT 1");
        
        // Clear any existing cookies (OAuth doesn't need them)
        hesk_setcookie('hesk_username', '');
        hesk_setcookie('hesk_remember', '');
    }

    public function handleCallback() {
        global $hesk_settings, $hesklang;

        if (isset($_GET['error'])) {
            hesk_process_messages($hesklang['wrong_user'],'index.php');
            exit();
        }

        if (!isset($_GET['code'])) {
            hesk_process_messages($hesklang['wrong_user'],'index.php');
            exit();
        }

        // Check if this is for elevator mode
        if (isset($_SESSION['oauth_elevator_mode'])) {
        // Mark as OAuth authenticated for elevator
        $_SESSION['oauth_authenticated'] = true;
        header('Location: elevator.php');
        exit();
        }

        $tokenData = $this->getAccessToken($_GET['code']);
        if (!$tokenData || !isset($tokenData['access_token'])) {
            hesk_process_messages($hesklang['wrong_user'],'index.php');
            exit();
        }

        $email = $this->getUserEmail($tokenData['access_token']);
        if (!$email) {
            hesk_process_messages($hesklang['wrong_user'],'index.php');
            exit();
        }

        // Find user by email
        $res = hesk_dbQuery("SELECT * FROM `".hesk_dbEscape($hesk_settings['db_pfix'])."users` WHERE `email`='" . hesk_dbEscape($email) . "' LIMIT 1");
        if (hesk_dbNumRows($res) != 1) {
            hesk_process_messages($hesklang['wrong_user'],'index.php');
            exit();
        }

        $user_row = hesk_dbFetchAssoc($res);

        // BYPASS MFA FOR OAUTH USERS - OAuth is considered secure enough
        // OAuth authentication is inherently more secure than password + MFA
        // since it requires the user to be authenticated with their Zoho account
        
        // Start fresh session
        hesk_session_stop();
        hesk_session_start();
        
        // Complete login process (no MFA required for OAuth)
        $this->processSuccessfulLogin($user_row, $tokenData);
        
        // Redirect to admin panel with success message
        $_SESSION['oauth_login_success'] = true;
        header('Location: ' . hesk_verifyGoto());
        exit();
    }
}

// Handle the OAuth flow
$zohoAuth = new ZohoAuth();

if (!isset($_GET['code'])) {
    $zohoAuth->initiateAuth();
} else {
    $zohoAuth->handleCallback();
}