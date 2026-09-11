<?php

namespace ASMBS\SSO;

use GuzzleHttp\Client;

class SSO
{
    private string $logFile = '/tmp/sso-debug.log';

    /**
     * Membership.Product GUIDs that grant the vote_md capability.
     * Matched against the raw GUID, not the display name, so a rename of
     * the product in MemberSuite doesn't silently break voting access.
     */
    private const MD_PRODUCT_GUIDS = [
        '05885462-0071-c5c8-b31b-0b498da7a5c1',
        '05885462-0071-c0c7-6b53-0b498da7e0bb',
        '05885462-0071-cd09-b325-0b4a0b99af04',
        '05885462-0071-c722-1393-0b48bcb2a570',
        '05885462-0071-ce0d-6958-0b48bcb26bf5',
    ];

    /**
     * Membership.Product GUIDs that grant the vote_ih capability.
     */
    private const IH_PRODUCT_GUIDS = [
        '05885462-0071-cf52-6e6d-0b498da28f79',
        '05885462-0071-cabe-548b-0b4a0ba05536',
        '05885462-0071-c126-a69c-0b48bcb424a4',
    ];

    public function __construct()
    {
        add_action('template_redirect', [$this, 'handle'], 1);
    }

    public function handle(): void
    {
        if (empty($_GET['tokenGUID'] ?? '')) {
            return;
        }

        $tokenGUID = sanitize_text_field($_GET['tokenGUID']);
        $client    = new Client();

        // tokenGUID -> big SSO token
        $response    = $client->get('https://rest.membersuite.com/platform/v2/regularSSO', [
            'query'   => [
                'partitionKey' => $_ENV['MS_PARTITION_KEY'],
                'tokenGUID'    => $tokenGUID,
            ],
            'headers' => ['Accept' => 'application/json'],
        ]);
        $bigSSOToken = $response->getBody()->getContents();

        // big SSO token -> user information
        $response     = $client->get('https://rest.membersuite.com/platform/v2/whoami', [
            'headers' => [
                'Accept'        => 'application/json',
                'Authorization' => 'AuthToken ' . $bigSSOToken,
            ],
        ]);
        $bodyUserJson = json_decode($response->getBody()->getContents(), true);

        // Capture and validate returnTo
        $returnTo = $_GET['returnTo'] ?? '';
        if (!empty($returnTo)) {
            $returnTo   = urldecode($returnTo);
            $siteHost   = parse_url(home_url(), PHP_URL_HOST);
            $returnHost = parse_url($returnTo, PHP_URL_HOST);
            if ($returnHost !== $siteHost) {
                $returnTo = home_url('/');
            }
        } else {
            $returnTo = home_url('/');
        }

        $this->log('Return URL', ['returnTo' => $returnTo]);

        try {
            $whoami     = $this->executeSearchMS($bodyUserJson['ownerId']);
            $this->log('Raw whoami', $whoami);
            $wp_user_id = $this->lookupWPAccount($whoami);
            $this->logWPUser($wp_user_id, $whoami);
        } catch (\Exception $e) {
            $this->log('SSO fatal error', [
                'message' => $e->getMessage(),
                'file'    => $e->getFile(),
                'line'    => $e->getLine(),
            ]);
            wp_die('Login failed. Please contact ASMBS. Error: ' . $e->getMessage());
        }

        wp_safe_redirect($returnTo);
        exit;
    }

    private function getMSToken(): string
    {
        $client   = new Client();
        $response = $client->post('https://rest.membersuite.com/platform/v2/loginUser/36893', [
            'json'    => [
                'email'    => $_ENV['MS_EMAIL'],
                'password' => $_ENV['MS_PASSWORD'],
            ],
            'headers' => ['Accept' => 'application/json'],
        ]);

        $data = json_decode($response->getBody()->getContents(), true);
        return $data['data']['idToken'];
    }

    public function executeSearchMS(string $guid): array
    {
        $client   = new Client();
        $response = $client->post('https://rest.membersuite.com/platform/v2/dataSuite/executeSearch', [
            'json'    => [
                // Membership.Product added alongside Membership.Type.name —
                // Product is the GUID used for vote_md/vote_ih capability
                // grants; Type.name is kept only for the mem_type WP meta
                // label (see resolveType()).
                'msql' => "select top 1 ID, LocalID, FirstName, LastName, EmailAddress, Membership.ReceivesMemberBenefits, Membership.Product, Membership.Type.name, Status.Name from Individual where (ID='" . $guid . "')"
            ],
            'headers' => [
                'Accept'        => 'application/json',
                'Authorization' => 'Bearer ' . $this->getMSToken(),
            ],
        ]);

        $data = json_decode($response->getBody()->getContents(), true);
        return $data['data'][0];
    }

    private function lookupWPAccount(array $whoami): int
    {
        $id      = $whoami['id'];
        $localID = $whoami['localID'];
        $email   = $whoami['emailAddress'];

        $this->log('Looking up user', ['guid' => $id, 'localID' => $localID, 'email' => $email]);

        // 1. Try GUID
        $users = get_users([
            'meta_key'   => 'mem_guid',
            'meta_value' => $id,
            'number'     => 1,
        ]);

        // 2. Fall back to localID
        if (empty($users)) {
            $this->log('GUID lookup failed, trying localID', ['localID' => $localID]);
            $users = get_users([
                'meta_key'   => 'mem_key',
                'meta_value' => $localID,
                'number'     => 1,
            ]);
        }

        // 3. Fall back to email
        if (empty($users)) {
            $this->log('localID lookup failed, trying email', ['email' => $email]);
            $userdata = get_user_by('email', $email);
            if ($userdata) {
                $this->log('Found user by email', ['wp_user_id' => $userdata->ID]);
                return $userdata->ID;
            }
        }

        // 4. Found via meta
        if (!empty($users)) {
            $this->log('Found user by meta', ['wp_user_id' => $users[0]->ID]);
            return $users[0]->ID;
        }

        // 5. No match — create new account
        $this->log('No user found, creating new account', ['email' => $email]);
        return $this->createWPAccount($whoami);
    }

    private function createWPAccount(array $whoami): int
    {
        $id           = $whoami['id'];
        $localID      = $whoami['localID'];
        $email        = $whoami['emailAddress'];
        $firstName    = $whoami['firstName'];
        $lastName     = $whoami['lastName'];
        $typeName     = $whoami['membership.Type.name'];
        $productGuid  = $whoami['membership.Product'] ?? null;
        $benefits     = $whoami['membership.ReceivesMemberBenefits'];
        $statusName   = $whoami['status.Name'];

        $this->log('Creating new WP account', ['email' => $email, 'id' => $id, 'localID' => $localID]);

        $wpRole   = RoleResolver::resolve($typeName, $benefits);
        $wpStatus = $this->resolveStatus($statusName);
        $wpType   = $this->resolveType($typeName);

        if (empty($wpRole)) {
            $this->log('No membership record found, defaulting to subscriber', ['email' => $email]);
            $wpRole = 'subscriber';
        }

        $user_id = wp_insert_user([
            'user_login' => sanitize_user($email),
            'user_email' => sanitize_email($email),
            'user_pass'  => wp_generate_password(32, true),
            'first_name' => sanitize_text_field($firstName),
            'last_name'  => sanitize_text_field($lastName),
            'role'       => $wpRole,
        ]);

        if (is_wp_error($user_id)) {
            $this->log('User creation failed', ['email' => $email, 'error' => $user_id->get_error_message()]);
            wp_die('User provisioning failed. Please contact ASMBS.');
        }

        $this->log('WP user created', ['wp_user_id' => $user_id, 'role' => $wpRole]);

        update_user_meta($user_id, 'mem_guid', $id);
        update_user_meta($user_id, 'mem_key', $localID);
        update_user_meta($user_id, 'mem_status', $wpStatus);
        update_user_meta($user_id, 'mem_type', $wpType);

        // Fetch the user object unconditionally — needed for both the
        // active-status capability below and the benefits-based vote_*
        // capabilities that already existed.
        $user = get_user_by('id', $user_id);

        // Grants access to other members' opt-in personal info on
        // provider profile pages (member-profile.php checks
        // current_user_can('view_member_content')). Based on
        // Membership.ReceivesMemberBenefits — same signal already used
        // elsewhere in this file (vote_md/vote_ih) to mean "active."
        if ($benefits === true) {
            $user->add_cap('view_member_content');
            $this->log('Granted view_member_content', ['wp_user_id' => $user_id, 'benefits' => $benefits]);
        } else {
            $user->remove_cap('view_member_content');
        }

        // vote_md / vote_ih are now granted by Membership.Product GUID
        // rather than the Type.name display string, so a rename of the
        // product in MemberSuite doesn't silently break voting access.
        if ($benefits === true && $productGuid !== null) {
            if (in_array($productGuid, self::MD_PRODUCT_GUIDS, true)) {
                $user->add_cap('vote_md');
                $this->log('Granted vote_md', ['wp_user_id' => $user_id, 'productGuid' => $productGuid]);
            }
            if (in_array($productGuid, self::IH_PRODUCT_GUIDS, true)) {
                $user->add_cap('vote_ih');
                $this->log('Granted vote_ih', ['wp_user_id' => $user_id, 'productGuid' => $productGuid]);
            }
        }

        return $user_id;
    }

    private function logWPUser(int $wp_user_id, array $whoami): void
    {
        $user        = get_user_by('id', $wp_user_id);
        $typeName    = $whoami['membership.Type.name'];
        $productGuid = $whoami['membership.Product'] ?? null;
        $benefits    = $whoami['membership.ReceivesMemberBenefits'];

        if ($typeName === null || $benefits === null) {
            $this->log('No membership record found, preserving existing role', [
                'wp_user_id' => $wp_user_id,
                'email'      => $whoami['emailAddress'],
            ]);
        } else {
            $wpRole = RoleResolver::resolve($typeName, $benefits);
            $this->log('Logging in user', ['wp_user_id' => $wp_user_id, 'role' => $wpRole]);
            $user->set_role($wpRole);

            // vote_md / vote_ih re-evaluated by Product GUID on every
            // login, so a product change in MemberSuite takes effect
            // immediately rather than only at account creation.
            if ($benefits === true && $productGuid !== null) {
                if (in_array($productGuid, self::MD_PRODUCT_GUIDS, true)) {
                    $user->add_cap('vote_md');
                } else {
                    $user->remove_cap('vote_md');
                }

                if (in_array($productGuid, self::IH_PRODUCT_GUIDS, true)) {
                    $user->add_cap('vote_ih');
                } else {
                    $user->remove_cap('vote_ih');
                }
            } else {
                $user->remove_cap('vote_md');
                $user->remove_cap('vote_ih');
            }
        }

        // Grants/revokes access to other members' opt-in personal info
        // on provider profile pages, re-evaluated on every login so a
        // benefits change in MemberSuite (e.g. lapsed membership) takes
        // effect immediately rather than only at account creation.
        // Same ReceivesMemberBenefits signal used for vote_md/vote_ih.
        if ($benefits === true) {
            $user->add_cap('view_member_content');
        } else {
            $user->remove_cap('view_member_content');
        }

        // Backfill missing meta for all users
        $this->backfillMeta($wp_user_id, $whoami);

        // Log the user in
        wp_clear_auth_cookie();
        wp_set_current_user(0);
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true);
        do_action('wp_login', $user->user_login, $user);
    }

    private function backfillMeta(int $wp_user_id, array $whoami): void
    {
        $typeName = $whoami['membership.Type.name'];

        if (empty(get_user_meta($wp_user_id, 'mem_guid', true))) {
            update_user_meta($wp_user_id, 'mem_guid', $whoami['id']);
            $this->log('Backfilled mem_guid', ['wp_user_id' => $wp_user_id, 'guid' => $whoami['id']]);
        }

        if (empty(get_user_meta($wp_user_id, 'mem_key', true))) {
            update_user_meta($wp_user_id, 'mem_key', $whoami['localID']);
            $this->log('Backfilled mem_key', ['wp_user_id' => $wp_user_id, 'localID' => $whoami['localID']]);
        }

        if (!empty($whoami['status.Name']) && empty(get_user_meta($wp_user_id, 'mem_status', true))) {
            $wpStatus = $this->resolveStatus($whoami['status.Name']);
            update_user_meta($wp_user_id, 'mem_status', $wpStatus);
            $this->log('Backfilled mem_status', ['wp_user_id' => $wp_user_id, 'status' => $wpStatus]);
        }

        if (!empty($typeName) && empty(get_user_meta($wp_user_id, 'mem_type', true))) {
            $wpType = $this->resolveType($typeName);
            update_user_meta($wp_user_id, 'mem_type', $wpType);
            $this->log('Backfilled mem_type', ['wp_user_id' => $wp_user_id, 'type' => $wpType]);
        }
    }

    private function resolveStatus(?string $statusName): string
    {
        return match ($statusName) {
            'Active'           => 'A',
            'Non-Member'       => 'N',
            'Inactive'         => 'I',
            'Deceased'         => 'Z',
            'Not Approved'     => 'X',
            'Expired (Lapsed)' => 'E',
            'Withdrawn'        => 'R',
            'Senior'           => 'S',
            'Distinguished'    => 'D',
            'Terminated'       => 'T',
            default            => '',
        };
    }

    /**
     * Feeds the mem_type WordPress meta label only — not used for any
     * access-control decision. vote_md/vote_ih are decided by Product
     * GUID (see MD_PRODUCT_GUIDS / IH_PRODUCT_GUIDS above), independent
     * of this method.
     */
    private function resolveType(?string $typeName): string
    {
        return match ($typeName) {
            'Surgeon/Physician Membership',
            'Surgeon/Physician Membership Renewal' => 'MD',
            'Candidate Member'                     => 'CM',
            'Corporate Council Representative'     => 'CC',
            'Integrated Health',
            'Integrated Health Renewal'            => 'IH',
            'International',
            'International Renewal'                => 'IN',
            'Application'                          => 'AP',
            'Friend'                               => 'FR',
            default                                => '',
        };
    }

    private function log(string $message, array $context = []): void
    {
        $timestamp = date('Y-m-d H:i:s');
        $entry     = "[{$timestamp}] {$message}";
        if (!empty($context)) {
            $entry .= ' ' . json_encode($context, JSON_PRETTY_PRINT);
        }
        error_log($entry . PHP_EOL, 3, $this->logFile);
    }
    public function lookupByGuid(string $guid): array
    {
        return $this->executeSearchMS($guid);
    }
}