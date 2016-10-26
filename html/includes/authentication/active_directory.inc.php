<?php

// easier to rewrite for Active Directory than to bash it into existing LDAP implementation

// disable certificate checking before connect if required
if (isset($config['auth_ad_check_certificates']) &&
          !$config['auth_ad_check_certificates']) {
    putenv('LDAPTLS_REQCERT=never');
};

if (isset($config['auth_ad_debug']) && $config['auth_ad_debug']) {
    ldap_set_option(null, LDAP_OPT_DEBUG_LEVEL, 7);
}

$ldap_connection = @ldap_connect($config['auth_ad_url']);

// disable referrals and force ldap version to 3

ldap_set_option($ldap_connection, LDAP_OPT_REFERRALS, 0);
ldap_set_option($ldap_connection, LDAP_OPT_PROTOCOL_VERSION, 3);

function authenticate($username, $password)
{
    global $config, $ldap_connection, $auth_error;

    if ($ldap_connection) {
        // bind with sAMAccountName instead of full LDAP DN
        if ($username && $password && ldap_bind($ldap_connection, "{$username}@{$config['auth_ad_domain']}", $password)) {
            // group membership in one of the configured groups is required
            if (isset($config['auth_ad_require_groupmembership']) &&
                $config['auth_ad_require_groupmembership']) {
                $search = ldap_search(
                    $ldap_connection,
                    $config['auth_ad_base_dn'],
                    get_auth_ad_user_filter($username),
                    array('memberof', 'mail', 'displayname')
                );
                
                $entries = ldap_get_entries($ldap_connection, $search);
                unset($entries[0]['memberof']['count']); //remove the annoying count
                $group_list = $entries[0]['memberof'];
                $email = $entries[0]['mail'][0];
                $display_name = $entries[0]['displayname'][0];

                foreach ($group_list as $entry) {
                    $group_cn = get_cn($entry);
                    if (isset($config['auth_ad_groups'][$group_cn]['level'])) {
                        // user is in one of the defined groups
                        $highest_userlevel = get_maxuserlevel($group_list);
                        if (user_exists($username)) {
                            update_user(get_userid($username), $display_name, $highest_userlevel, 0, $email);
                        } else {
                            adduser($username, '', $highest_userlevel, $email, $display_name, 0);
                        }
                        return 1;
                    }
                }

                if (isset($config['auth_ad_debug']) && $config['auth_ad_debug']) {
                    if ($entries['count'] == 0) {
                        $auth_error = 'No groups found for user, check base dn';
                    } else {
                        $auth_error = 'User is not in one of the required groups';
                    }
                } else {
                    $auth_error = 'Invalid credentials';
                }

                return 0;
            } else {
                // group membership is not required and user is valid
                adduser($username);
                return 1;
            }
        }
    die("username, password or bind failed");
    }

    if (!isset($password) || $password == '') {
        $auth_error = "A password is required";
    } elseif (isset($config['auth_ad_debug']) && $config['auth_ad_debug']) {
        ldap_get_option($ldap_connection, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extended_error);
        $auth_error = ldap_error($ldap_connection).'<br />'.$extended_error;
    } else {
        $auth_error = ldap_error($ldap_connection);
    }

    return 0;
}

function passwordscanchange()
{
    // not supported so return 0
    return 0;
}


function changepassword()
{
    // not supported so return 0
    return 0;
}


function can_update_users()
{
    // not supported so return 0
    return 0;
}


function get_group_list()
{
    global $config;

    $ldap_groups   = array();

    // show all Active Directory Users by default
    $default_group = 'Users';

    if (isset($config['auth_ad_group'])) {
        if ($config['auth_ad_group'] !== $default_group) {
            $ldap_groups[] = $config['auth_ad_group'];
        }
    }

    if (!isset($config['auth_ad_groups']) && !isset($config['auth_ad_group'])) {
        $ldap_groups[] = get_dn($default_group);
    }

    foreach ($config['auth_ad_groups'] as $key => $value) {
        $ldap_groups[] = get_dn($key);
    }

    return $ldap_groups;
}

function get_maxuserlevel($member_groups)
{
    global $config;

    $userlevel = 0;

    // Loop the list and find the highest level
    foreach ($member_groups as $entry) {
        $group_cn = get_cn($entry);
        if (isset($config['auth_ad_groups'][$group_cn]['level']) &&
            $config['auth_ad_groups'][$group_cn]['level'] > $userlevel) {
            $userlevel = $config['auth_ad_groups'][$group_cn]['level'];
        }
    }

    return $userlevel;
}


function get_dn($samaccountname)
{
    global $config, $ldap_connection;


    $attributes = array('dn');
    $result = ldap_search(
        $ldap_connection,
        $config['auth_ad_base_dn'],
        get_auth_ad_group_filter($samaccountname),
        $attributes
    );
    $entries = ldap_get_entries($ldap_connection, $result);
    if ($entries['count'] > 0) {
        return $entries[0]['dn'];
    } else {
        return '';
    }
}

function get_cn($dn)
{
    $dn = str_replace('\\,', '~C0mmA~', $dn);
    preg_match('/[^,]*/', $dn, $matches, PREG_OFFSET_CAPTURE, 3);
    return str_replace('~C0mmA~', ',', $matches[0][0]);
}

function sid_from_ldap($sid)
{
        $sidUnpacked = unpack('H*hex', $sid);
        $sidHex = array_shift($sidUnpacked);
        $subAuths = unpack('H2/H2/n/N/V*', $sid);
        $revLevel = hexdec(substr($sidHex, 0, 2));
        $authIdent = hexdec(substr($sidHex, 4, 12));
        return 'S-'.$revLevel.'-'.$authIdent.'-'.implode('-', $subAuths);
}
