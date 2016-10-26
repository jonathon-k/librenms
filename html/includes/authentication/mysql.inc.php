<?php


function authenticate($username, $password)
{
    $encrypted_old = md5($password);
    $row           = dbFetchRow('SELECT username,password FROM `users` WHERE `username`= ?', array($username), true);
    if ($row['username'] && $row['username'] == $username) {
        // Migrate from old, unhashed password
        if ($row['password'] == $encrypted_old) {
            $row_type = dbFetchRow('DESCRIBE users password');
            if ($row_type['Type'] == 'varchar(34)') {
                changepassword($username, $password);
            }

            return 1;
        } elseif (substr($row['password'], 0, 3) == '$1$') {
            $row_type = dbFetchRow('DESCRIBE users password');
            if ($row_type['Type'] == 'varchar(60)') {
                if ($row['password'] == crypt($password, $row['password'])) {
                    changepassword($username, $password);
                }
            }
        }

        $hasher = new PasswordHash(8, false);
        if ($hasher->CheckPassword($password, $row['password'])) {
            return 1;
        }
    }//end if

    return 0;
}//end authenticate()


function passwordscanchange($username = '')
{
    /*
     * By default allow the password to be modified, unless the existing
     * user is explicitly prohibited to do so.
     */

    if (empty($username) || !user_exists($username)) {
        return 1;
    } else {
        return dbFetchCell('SELECT can_modify_passwd FROM users WHERE username = ?', array($username), true);
    }
}//end passwordscanchange()


function can_update_users()
{
    // supported so return 1
    return 1;
}//end can_update_users()


/**
 * From: http://code.activestate.com/recipes/576894-generate-a-salt/
 * This function generates a password salt as a string of x (default = 15) characters
 * ranging from a-zA-Z0-9.
 * @param $max integer The number of characters in the string
 * @author AfroSoft <scripts@afrosoft.co.cc>
 */
function generateSalt($max = 15)
{
    $characterList = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $i             = 0;
    $salt          = '';
    do {
        $salt .= $characterList{mt_rand(0, strlen($characterList))};
        $i++;
    } while ($i <= $max);

    return $salt;
}//end generateSalt()


function changepassword($username, $password)
{
    $hasher    = new PasswordHash(8, false);
    $encrypted = $hasher->HashPassword($password);
    return dbUpdate(array('password' => $encrypted), 'users', '`username` = ?', array($username));
}//end changepassword()
