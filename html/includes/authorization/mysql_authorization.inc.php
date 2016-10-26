<?php
/*
 * Module for separating Authentication from Authorization.  This is to allow Authentication through
 * another service, such as LDAP, and then determine existing users, user permission, etc via SQL
 * 
 */

function authorize()
{
    // Right now this checks the browser provided cookie against the information in the database
    if (isset($_COOKIE['sess_id'], $_COOKIE['token'], $_COOKIE['username'])) {
        $sess_id = clean($_COOKIE['sess_id']);
        $token = clean($_COOKIE['token']);

        $session = dbFetchRow("SELECT * FROM `session` WHERE session_value='$sess_id'", array(), true);
        if ($token === $session['session_token']) {
            $_SESSION['username'] = $_COOKIE['username'];
            return 1;
        } else {
            return 0;
        }
    } else {
        return 0;
    }
}//end authorize()


function user_exists($username)
{
    $return = @dbFetchCell('SELECT COUNT(*) FROM users WHERE username = ?', array($username), true);
    return $return;
}//end user_exists()


function get_userlevel($username)
{
    return dbFetchCell('SELECT `level` FROM `users` WHERE `username` = ?', array($username), true);
}//end get_userlevel()


function get_userid($username)
{
    return dbFetchCell('SELECT `user_id` FROM `users` WHERE `username` = ?', array($username), true);
}//end get_userid()


function deluser($username)
{
    dbDelete('bill_perms', '`user_name` =  ?', array($username));
    dbDelete('devices_perms', '`user_name` =  ?', array($username));
    dbDelete('ports_perms', '`user_name` =  ?', array($username));
    dbDelete('users_prefs', '`user_name` =  ?', array($username));
    dbDelete('users', '`user_name` =  ?', array($username));
    dbDelete('session', '`session_username` =  ?', array($username));
    return dbDelete('users', '`username` =  ?', array($username));
}//end deluser()


function get_userlist()
{
    return dbFetchRows('SELECT * FROM `users`');
}//end get_userlist()


function get_user($user_id)
{
    return dbFetchRow('SELECT * FROM `users` WHERE `user_id` = ?', array($user_id), true);
}//end get_user()


function update_user($user_id, $realname, $level, $can_modify_passwd, $email)
{
    dbUpdate(array('realname' => $realname, 'level' => $level, 'can_modify_passwd' => $can_modify_passwd, 'email' => $email), 'users', '`user_id` = ?', array($user_id));
}//end update_user()


function auth_usermanagement()
{
    return 1;
}//end auth_usermanagement()


function adduser($username, $password, $level, $email = '', $realname = '', $can_modify_passwd = 1, $description = '', $twofactor = 0)
{
    if (!user_exists($username)) {
        $hasher    = new PasswordHash(8, false);
        $encrypted = $hasher->HashPassword($password);
        $userid    = dbInsert(array('username' => $username, 'password' => $encrypted, 'level' => $level, 'email' => $email, 'realname' => $realname, 'can_modify_passwd' => $can_modify_passwd, 'descr' => $description, 'twofactor' => $twofactor), 'users');
        if ($userid == false) {
            return false;
        } else {
            foreach (dbFetchRows('select notifications.* from notifications where not exists( select 1 from notifications_attribs where notifications.notifications_id = notifications_attribs.notifications_id and notifications_attribs.user_id = ?) order by notifications.notifications_id desc', array($userid)) as $notif) {
                dbInsert(array('notifications_id'=>$notif['notifications_id'],'user_id'=>$userid,'key'=>'read','value'=>1), 'notifications_attribs');
            }
        }
        return $userid;
    } else {
        return false;
    }
}//end adduser()
