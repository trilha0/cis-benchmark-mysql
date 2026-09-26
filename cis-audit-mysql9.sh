#!/bin/bash
#
# script.: cis-audit-mysql9.sh
# version: 202609261515
# author.: braga [dot] marcos [at] gmail
# cdate..: 2026-09-15
#
help() {
    echo ""
    echo "Uso:"
    echo "./cis-audit-mysql9.sh {valid_login_path_entry}"
    echo "Ex.:"
    echo "./cis-audit-mysql9.sh root"
    echo ""
    exit 1
}

# validando o parâmetro login_path foi passado na execução do script
[[ -z "${1}" ]] && help
login_path=${1}

# variáveis
cur_date=$(date +%F_%H%M%S)
report_dir="cis_audit_${cur_date}"
# relatórios
txt_file="${report_dir}/report.txt"
csv_file="${report_dir}/report.csv"

# função para validar a conexão com o banco usando login_path
mysql_test() {
    if mysql --login-path="${login_path}" -e "select 1" >/dev/nul 2>&1
    then
        echo ""
    else
        echo -e "\nInvalid login_path entry"
        help
    fi
}

# validando se o login_path é válido
mysql_test

mysql_exec() {
    mysql --login-path="${login_path}" -N -B -e "$1"
}

pass() {
    >> "${csv_file}" echo "$1,PASS,$2"
}

fail() {
    >> "${csv_file}" echo "$1,FAIL,$2"
}

manual() {
    >> "${csv_file}" echo "$1,MANUAL,$2"
    >> "${txt_file}" echo "$1 $2 (Manual)"
}

section() {
    >> "${txt_file}" echo ""
    >> "${txt_file}" echo "###############################################################################"
    >> "${txt_file}" echo "$1"
    >> "${txt_file}" echo "###############################################################################"
}

mkdir -p "$report_dir"

> "${csv_file}" echo "CONTROL,STATUS,EVIDENCE"

section "# Chapter 1. Operating System Level Configuration"

mysqldir=$(mysql_exec "select variable_value from performance_schema.global_variables where variable_name = 'datadir'")

if [[ "${mysqldir}" == "/var/lib/mysql/" ]]
then
    fail "1.1" "Databases not on Non-System Partitions"
else
    pass "1.1" "Databases on Non-System Partitions"
fi


#    1.2 Use Dedicated Least Privileged Account for MySQL Daemon/Service
if ps -ef | grep -q "^mysql.*$"
then
    pass "1.2" "Dedicated least privileged account for MySQL Daemon/Service"
else
    fail "1.2" "Not dedicated least privileged account for MySQL Daemon/Service"
fi


#   1.3 Disable MySQL Command History"
result=$(find /home -name ".mysql_history")
result=$(find /root -name ".mysql_history")

if [ -n ${result} ]
then
    fail "1.3" "MySQL command history not disabled"
else
    pass "1.3" "MySQL command history disabled"
fi


#   1.4 Verify that the MYSQL_PWD environment variable is not in use
if grep MYSQL_PWD /proc/*/environ
then
    fail "1.4" "MYSQL_PWD environment variable is in use"
else
    pass "1.4" "MYSQL_PWD environment variable is not in use"
fi


#   1.5 Ensure interactive login is disabled
if getent passwd mysql | egrep -q "^.*[\/bin\/false|\/sbin\/nologin]$"
then
    pass "1.5" "Interactive login is disabled"
else
    pass "1.5" "Interactive login is enabled"
fi


#   1.6 Verify That 'MYSQL_PWD' is Not Set in Users' Profiles
if grep -qs MYSQL_PWD /root/.{bashrc,profile,bash_profile}
then
    fail "1.6" "MYSQL_PWD is set in users' profiles"
else
    pass "1.6" "MYSQL_PWD is not set in users' profiles"
fi


#   1.7 Ensure MySQL is Run Under a Sandbox Environment
if systemctl -q status mysqld 2>/dev/nul 1>&2
then
    pass "1.7" "MySQL is running under a sandbox environment"
else
    fail "1.7" "MySQL is not running under a sandbox environment"
fi

#
# CHAPTER 2
#
section "# Chapter 2. Installation and Planning "

#   2.1 Backup and Disaster Recovery

#     2.1.1 Backup Policy in Place
if crontab -l | grep -isq mysql; then result=1; fi
if grep -isq mysql /etc/crontab; then result=1; fi

if [[ ${result} = 1 ]]
then
    pass "2.1.1" "Backup policy in place"
else
    fail "2.1.1" "Backup policy not found"
fi

manual "2.1.2" "Verify Backups are Good"
manual "2.1.3" "Secure Backup Credentials"
manual "2.1.4" "The Backups Should be Properly Secured"

#     2.1.5 Point-in-Time Recovery
>>"${txt_file}" mysql_exec "SELECT VARIABLE_NAME, VARIABLE_VALUE, 'BINLOG - Log Expiration' as Note FROM performance_schema.global_variables where variable_name = 'binlog_expire_logs_seconds'"

binlog_expire_logs_seconds=$(mysql_exec "SELECT VARIABLE_VALUE FROM performance_schema.global_variables where variable_name = 'binlog_expire_logs_seconds'")

if [[ ${binlog_expire_logs_seconds} > 0 ]]
then
    pass "2.1.5" "Point-in-time recovery enabled"
else
    fail "2.1.5" "Point-in-time recovery not found"
fi

manual "2.1.6" "Disaster Recovery (DR) Plan"
manual "2.1.7" "Backup of Configuration and Related Files"

#   2.2 Data Encryption

#     2.2.1 Ensure Binary and Relay Logs are Encrypted
>>"${txt_file}" mysql_exec "SELECT VARIABLE_NAME, VARIABLE_VALUE, 'BINLOG - At Rest Encryption' as Note FROM performance_schema.global_variables where variable_name = 'binlog_encryption'"

binlog_encryption=$(mysql_exec "SELECT VARIABLE_VALUE FROM performance_schema.global_variables where variable_name = 'binlog_encryption'")

if [[ "${binlog_encryption}" == "ON" ]]
then
    pass "2.2.1" "Binary and Relay logs are encrypted"
else
    fail "2.2.1" "Binary and Relay logs are not encrypted"
fi

manual "2.3" "Dedicate the Machine Running MySQL"
manual "2.4" "Do Not Specify Passwords in the Command Line"
manual "2.5" "Do Not Reuse Usernames"


#   2.6 Ensure Non-Default, Unique Cryptographic Material is in Use
if openssl x509 -in /var/lib/mysql/server-cert.pem -subject -noout | grep -q Auto_Generated_Server_Certificate
then
    fail "2.6" "Non-default, unique cryptographic material is not in use"
else
    pass "2.6" "Non-default, unique cryptographic material is in use"
fi


#   2.7 Ensure 'password_lifetime' is Less Than or Equal to '365'
default_password_lifetime=$(mysql_exec "SELECT VARIABLE_VALUE FROM performance_schema.global_variables where VARIABLE_NAME like 'default_password_lifetime'")

if [[ ${default_password_lifetime} = 0 || ${default_password_lifetime} > 365 ]]
then
    fail "2.7" "Password lifetime is NOT less than or equal to 365"
else
    pass "2.7" "Password lifetime is less than or equal to 365"
fi


#   2.8 Ensure Password Resets Require Strong Passwords
password_history=$(mysql_exec "SELECT VARIABLE_VALUE FROM performance_schema.global_variables where VARIABLE_NAME = 'password_history'")
password_reuse_interval=$(mysql_exec "SELECT VARIABLE_VALUE FROM performance_schema.global_variables where VARIABLE_NAME = 'password_reuse_interval'")

if [[ ${password_history} = 0 || ${password_reuse_interval} = 0 ]]
then
    fail "2.8" "Password resets NOT require strong passwords"
else
    pass "2.8" "Password resets require strong passwords"
fi


#   2.9 Require Current Password for Password Reset
password_require_current=$(mysql_exec "SELECT VARIABLE_VALUE FROM performance_schema.global_variables where VARIABLE_NAME = 'password_require_current'")

if [[ "${password_require_current}" == "OFF" ]]
then
    fail "2.9" "Not require current password for password reset"
else
    pass "2.9" "Require current password for password reset"
fi


manual "2.10" "Use Dual Passwords to Enable Higher Frequency Password Rotation"
>>"${txt_file}" mysql --login-path=${login_path} -e 'SELECT user, host FROM mysql.user WHERE length(user_attributes->"$.additional_password")>0'
manual "2.11" "Lock Out Accounts if Not Currently in Use"
>>"${txt_file}" mysql --login-path=${login_path} -e "select user, host, account_locked from mysql.user"


#   2.12 Ensure AES Encryption Mode for AES_ENCRYPT/AES_DECRYPT is Configured Correctly
block_encryption_mode=$(mysql_exec "select @@block_encryption_mode")

if [[ "${block_encryption_mode:0:7}" != "aes-256" ]]
then
    fail "2.12" "AES encryption mode for AES_ENCRYPT/AES_DECRYPT is NOT configured correctly"
else
    pass "2.12" "AES encryption mode for AES_ENCRYPT/AES_DECRYPT is configured correctly"
fi


manual "2.13" "Ensure Socket Peer-Credential Authentication is Used Appropriately"
>>"${txt_file}" mysql_exec "SELECT PLUGIN_NAME, PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME LIKE 'auth%'"
>>"${txt_file}" mysql_exec "select user, host, plugin from mysql.user where plugin = 'auth_socket'"


manual "2.14" "Ensure MySQL is Bound to an IP Address"
>>"${txt_file}" mysql --login-path=${login_path} -e "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'bind_address'"


#   2.15 Limit Accepted Transport Layer Security (TLS) Versions
if mysql --login-path=${login_path} -e "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'tls_version'" | grep -qE '(^|,)TLSv1(\.1)?(,|$)'
then
    pass "2.15" "Limit Accepted Transport Layer Security"
else
    fail "2.15" "Accepted Transport Layer Security not limited"
fi


#   2.16 Require Client-Side Certificates (X.509)
ssl_type_session=$(mysql --login-path=${login_path} -N -e "select ssl_type from mysql.user where user not in ('mysql.infoschema', 'mysql.session', 'mysql.sys')")

if [[ -z "${ssl_type_session}" ]]
then
    fail "2.16" "Required client-side certificates not found"
else
    pass "2.16" "Required client-side certificates"
fi


#   2.17 Ensure Only Approved Ciphers are Used
ssl_cipher=$(mysql --login-path=${login_path} -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'ssl_cipher'")
tls_ciphersuites=$(mysql --login-path=${login_path} -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'tls_ciphersuites'")

if [[ "${ssl_cipher}" == "ECDHE-ECDSA-AES128-GCM-SHA256" || "${tls_ciphersuites}" == "TLS_AES_256_GCM_SHA384" ]]
then
    pass "2.17" "Only approved ciphers are used"
else
    fail "2.17" "Ciphers are not used"
fi


#   2.18 Implement Connection Delays to Limit FAILed Login Attempts
connection_control=$(mysql --login-path=${login_path} -N -e "SELECT PLUGIN_NAME, PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME = 'connection_control'")
connection_control_failed_login_attempts=$(mysql --login-path=${login_path} -N -e "SELECT PLUGIN_NAME, PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME = 'connection_control_failed_login_attempts'")

#mysql --login-path=${login_path} -e "select host, user, JSON_EXTRACT(user_attributes, '$.Password_locking.FAILed_login_attempts') as FAILed_login_attempts from mysql.user"

if [[ "${connection_control}" == "ACTIVE" && "${connection_control_failed_login_attempts}" == "ACTIVE" ]]
then
    pass "2.18" "Connection limit failed login attempts"
else
    fail "2.18" "Connection limit not failed login attempts"
fi


#   2.19 Ensure FIPS 140-3 OpenSSL Cryptography Is Used
ssl_fips_mode=$(mysql --login-path=${login_path} -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'ssl_fips_mode'")

if [[ "${ssl_fips_mode}" = "OFF" ]]
then
    fail "2.19" "FIPS 140-3 OpenSSL Cryptography is not used"
else
    pass "2.19" "FIPS 140-3 OpenSSL Cryptography is used"
fi

#
# CHAPTER 3
#
section "# Chapter 3. File Permissions"

#   3.1 Ensure 'datadir' Has Appropriate Permissions
datadir=$(mysql --login-path=${login_path} -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME LIKE 'datadir'")

if ls -ld ${datadir} | grep -q "drwxr-x---.*mysql.*mysql"
then
    pass "3.1" "'datadir' has appropriate permissions"
else
    fail "3.1" "'datadir' doesn't have appropriate permissions"
fi


#   3.2 Ensure 'log_bin_basename' Files Have Appropriate Permissions
log_bin_basename=$(mysql --login-path=${login_path} -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME LIKE 'log_bin_basename'")

if ls -l ${log_bin_basename}* | grep -q "\-rw-r-----.*mysql.*mysql"
then
    pass "3.2" "'log_bin_basename' files have appropriate permissions"
else
    fail "3.2" "'log_bin_basename' files don't have appropriate permissions"
fi


#   3.3 Ensure 'log_error' Has Appropriate Permissions
log_error=$(mysql --login-path=${login_path} -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME LIKE 'log_error'")

if ls -l ${log_error}* | grep -q "\-rw-------.*mysql.*mysql"
then
    pass "3.3" "'log_error' has appropriate permissions"
else
    fail "3.3" "'log_error' doesn't have appropriate permissions"
fi


#   3.4 Ensure 'slow_query_log' Has Appropriate Permissions
slow_query_log=$(mysql --login-path=${login_path} -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME LIKE 'slow_query_log'")

if [[ "${slow_query_log}" == "OFF" ]]
then
    >> "${txt_file}" echo "3.4 'slow_query_log' is OFF"
else
    slow_query_log_file=$(mysql --login-path=${login_path} -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'slow_query_log_file'")
    if ls -l ${slow_query_log_file} | grep -q "\-rw-r-----.*mysql.*mysql"
    then
        pass "3.4" "'slow_query_log_file' has appropriate permissions"
    else
        fail "3.4" "'slow_query_log_file' doesn't have appropriate permissions"
    fi
fi


#   3.5 Ensure 'relay_log_basename' Files Have Appropriate Permissions
relay_log_basename=$(mysql --login-path=${login_path} -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'relay_log_basename'")

if [[ -f ${relay_log_basename}* ]]
then
    if stat -c '%A %U %G' ${relay_log_basename}* | grep -Eq '^(-rw-r-----|-rw-rw----)[[:space:]]+mysql[[:space:]]+mysql$'
    then
        pass "3.5" "'relay_log_basename' has appropriate permissions"
    else
        fail "3.5" "'relay_log_basename' doesn't have appropriate permissions"
    fi
else
    >> "${txt_file}" echo "3.5 'relay_log_basename' not found"
fi


#   3.6 Ensure 'general_log_file' Has Appropriate Permissions
general_log=$(mysql --login-path=${login_path} -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'general_log'")
general_log_file=$(mysql --login-path=${login_path} -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'general_log_file'")

if [[ "${general_log}" == "OFF" ]]
then
    >> "${txt_file}" echo "3.5 'general_log' is OFF"
else
    if stat -c '%A %U %G' ${general_log_file} | grep -q '^-rw-------.*mysql.*mysql'
    then
        pass "3.5" "'general_log_file' has appropriate permissions"
    else
        fail "3.5" "'general_log_file' doesn't have appropriate permissions"
    fi
fi


#   3.7 Ensure SSL Key Files Have Appropriate Permissions
data=$(mysql --login-path=${login_path} -N -e "SELECT * FROM performance_schema.global_variables WHERE REGEXP_LIKE(VARIABLE_NAME,'^.*ssl_(ca|capath|cert|crl|crlpath|key)$') AND VARIABLE_VALUE <> ''")
res=true
while read -r variable value
do
    if stat -c '%a %U %G' ${datadir}${value} | grep -q '644.*mysql.*mysql'
    then
        echo "" > /dev/nul
    else
        res=false
    fi
done <<< ${data}

if $res
then
    pass "3.7" "SSL key files have appropriate permissions"
else
    fail "3.7" "SSL key files don't have appropriate permissions"
fi


#   3.8 Ensure Plugin Directory Has Appropriate Permissions
plugin_dir=$(mysql --login-path=${login_path} -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME LIKE 'plugin_dir'")
per=$(stat -c '%a' ${plugin_dir})

if [[ ${per} == 550 || ${per} == 554 ]]
then
    pass "3.8" "Plugin directory has appropriate permissions"
else
    fail "3.8" "Plugin directory doesn't have appropriate permissions"
fi




##################################################################
pass_count=$(grep -c ',PASS,' "${csv_file}" || true)
fail_count=$(grep -c ',FAIL,' "${csv_file}" || true)
manual_count=$(grep -c ',MANUAL,' "${csv_file}" || true)

{
echo ""
echo "SUMMARY"
echo "PASS   : ${pass_count}"
echo "FAIL   : ${fail_count}"
echo "MANUAL : ${manual_count}"
} >> "${txt_file}"

echo "Reports generated in ${report_dir}"
##################################################################



#   3.8 Ensure Plugin Directory Has Appropriate Permissions
plugin_dir=$(mysql --login-path=${login_path} -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME LIKE 'plugin_dir'")
per=$(stat -c '%a' ${plugin_dir})

if [[ ${per} == 550 || ${per} == 554 ]]
then
    pass "3.8" "Plugin directory has appropriate permissions"
else
    fail "3.8" "Plugin directory doesn't have appropriate permissions"
fi
