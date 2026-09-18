#!/bin/bash
#
# script.: cis_audit_mysql.sh
# author.: braga [dot] marcos [at] gmail
# cdate..: 2026-09-15
# update.: 2026-09-18
#
[[ -z "${1}" ]] && echo "Falta parâmetro login-path" && exit 1

login_path=${1}

# variáveis
cur_date=$(date +%F_%H%M%S)
report_dir="cis_audit_${cur_date}"

txt_file="${report_dir}/report.txt"
csv_file="${report_dir}/report.csv"

mkdir -p "$report_dir"

mysql_exec() {
    mysql --login-path="${login_path}" -N -B -e "$1"
}

pass() {
    echo "$1,PASS,$2" >> "${csv_file}"
}

fail() {
    echo "$1,FAIL,$2" >> "${csv_file}"
}

manual() {
    echo "$1,MANUAL,$2" >> "${csv_file}"
    echo "$1 $2 (Manual)" >> "${txt_file}"
}

section() {
    echo "" >> "${txt_file}"
    echo "###############################################################################" >> "${txt_file}"
    echo "$1" >> "${txt_file}"
    echo "###############################################################################" >> "${txt_file}"
}


echo "CONTROL,STATUS,EVIDENCE" > "${csv_file}"

section "# Chapter 1. Operating System Level Configuration"

mysqldir=$(mysql_exec "select variable_value from performance_schema.global_variables where variable_name = 'datadir'")

if [[ "$mysqldir" == "/var/lib/mysql/" ]]
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

if [ -n $result ]
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

if [[ $result = 1 ]]
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

if [[ $binlog_expire_logs_seconds > 0 ]]
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

if [[ "$binlog_encryption" == "ON" ]]
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

if [[ $default_password_lifetime = 0 || $default_password_lifetime > 365 ]]
then
    fail "2.7" "Password lifetime is NOT less than or equal to 365"
else
    pass "2.7" "Password lifetime is less than or equal to 365"
fi


#   2.8 Ensure Password Resets Require Strong Passwords

password_history=$(mysql_exec "SELECT VARIABLE_VALUE FROM performance_schema.global_variables where VARIABLE_NAME = 'password_history'")

password_reuse_interval=$(mysql_exec "SELECT VARIABLE_VALUE FROM performance_schema.global_variables where VARIABLE_NAME = 'password_reuse_interval'")

if [[ $password_history = 0 || $password_reuse_interval = 0 ]]
then
    fail "2.8" "Password resets NOT require strong passwords"
else
    pass "2.8" "Password resets require strong passwords"
fi


#   2.9 Require Current Password for Password Reset

password_require_current=$(mysql_exec "SELECT VARIABLE_VALUE FROM performance_schema.global_variables where VARIABLE_NAME = 'password_require_current'")

if [[ "$password_require_current" == "OFF" ]]
then
    fail "2.9" "Not require current password for password reset"
else
    pass "2.9" "Require current password for password reset"
fi


manual "2.10" "Use Dual Passwords to Enable Higher Frequency Password Rotation"
>>"${txt_file}" mysql --login-path=$login_path -e 'SELECT user, host FROM mysql.user WHERE length(user_attributes->"$.additional_password")>0'
manual "2.11" "Lock Out Accounts if Not Currently in Use"
>>"${txt_file}" mysql --login-path=$login_path -e "select user, host, account_locked from mysql.user"

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
>>"${txt_file}" mysql --login-path=$login_path -e "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'bind_address'"


#   2.15 Limit Accepted Transport Layer Security (TLS) Versions
if mysql --login-path=$login_path -e "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'tls_version'" | grep -qE '(^|,)TLSv1(\.1)?(,|$)'
then
    pass "2.15" "Limit Accepted Transport Layer Security"
else
    fail "2.15" "Accepted Transport Layer Security not limited"
fi


#   2.16 Require Client-Side Certificates (X.509)
ssl_type_session=$(mysql --login-path=$login_path -N -e "select ssl_type from mysql.user where user not in ('mysql.infoschema', 'mysql.session', 'mysql.sys')")

if [[ -z "$ssl_type_session" ]]
then
    fail "2.16" "Required client-side certificates not found"
else
    pass "2.16" "Required client-side certificates"
fi


#   2.17 Ensure Only Approved Ciphers are Used
ssl_cipher=$(mysql --login-path=$login_path -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'ssl_cipher'")

tls_ciphersuites=$(mysql --login-path=$login_path -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'tls_ciphersuites'")

if [[ "$ssl_cipher" == "ECDHE-ECDSA-AES128-GCM-SHA256" || "$tls_ciphersuites" == "TLS_AES_256_GCM_SHA384" ]]
then
    pass "2.17" "Only approved ciphers are used"
else
    fail "2.17" "Ciphers are not used"
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





#   2.18 Implement Connection Delays to Limit FAILed Login Attempts

mysql --login-path=$login_path -e "SELECT PLUGIN_NAME, PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME LIKE 'connection%'"

mysql --login-path=$login_path -e "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME LIKE 'connection_control%'"

mysql --login-path=$login_path -e "select host, user, JSON_EXTRACT(user_attributes, '$.Password_locking.FAILed_login_attempts') as FAILed_login_attempts from mysql.user"


echo "#   2.19 Ensure FIPS 140-3 OpenSSL Cryptography Is Used"

ssl_fips_mode=$(mysql --login-path=$login_path -N -e "SELECT @@ssl_fips_mode")

[[ "$ssl_fips_mode" = "OFF" ]] && echo "FAIL" || echo "PASS"


echo "# 3 File Permissions "

echo "#   3.1 Ensure 'datadir' Has Appropriate Permissions"

datadir=$(mysql --login-path=$login_path -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME LIKE 'datadir'")

ls -ld $datadir | grep "drwxr-x---.*mysql.*mysql" && echo "PASS" || echo "FAIL"


echo "#   3.2 Ensure 'log_bin_basename' Files Have Appropriate Permissions"

log_bin_basename=$(mysql --login-path=$login_path -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME LIKE 'log_bin_basename'")

ls -l $log_bin_basename* | grep -q "\-rw-r-----.*mysql.*mysql" && echo "PASS" || echo "FAIL"

###ls -l | egrep '^-(?![r|w]{2}-[r|w]{2}----.*mysql\s*mysql).*$log_bin_basename.*$'


echo "#   3.3 Ensure 'log_error' Has Appropriate Permissions"

log_error=$(mysql --login-path=$login_path -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME LIKE 'log_error'")

ls -l $log_error* | grep -q "\-rw-------.*mysql.*mysql" && echo "PASS" || echo "FAIL"


echo "#   3.4 Ensure 'slow_query_log' Has Appropriate Permissions"

slow_query_log=$(mysql --login-path=$login_path -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME LIKE 'slow_query_log'")

slow_query_log_file=$(mysql --login-path=$login_path -N -e "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'slow_query_log_file'")

ls -l $slow_query_log_file | grep -q "\-rw-r-----.*mysql.*mysql" && echo "PASS" || echo "FAIL"


echo "#   3.5 Ensure 'relay_log_basename' Files Have Appropriate Permissions"








#!/bin/bash
version=202609162039
cmd_mysql_config_editor=/usr/bin/mysql_config_editor
cmd_mysql=/usr/bin/mysql
cmd_telnet=/usr/bin/telnet
cmd_awk=/usr/bin/awk
cmd_grep=/usr/bin/grep
cmd_tail=/usr/bin/tail
cmd_timeout=/usr/bin/timeout
loginpaths=($(mysql_config_editor print --all | $cmd_grep ^'\[' | tr -d "[\[\]]"))
variable_input="$1"
for ((i=0; i<${#loginpaths[*]}; i++)); do
  $cmd_mysql --login-path=${loginpaths[i]} -A --get-server-public-key -e "SELECT VARIABLE_VALUE as ${loginpaths[i]} FROM performance_schema.global_variables WHERE VARIABLE_NAME = '$variable_input'"
done

exit 0







SELECT
    digest_text AS query_resumida,
    count_star AS execucoes,
    ROUND(sum_timer_wait / 1000000000000, 2) AS tempo_total_seg,
    ROUND(avg_timer_wait / 1000000000000, 4) AS media_seg,
    sum_rows_examined AS linhas_examinadas,
    sum_rows_sent AS linhas_retornadas,
    ROUND(sum_rows_examined / NULLIF(sum_rows_sent, 0), 0) AS ratio_exam_vs_ret
FROM performance_schema.events_statements_summary_by_digest
WHERE schema_name = 'play_db'
and digest_text like '%nsu%conta_corrente_distribuidor%'
ORDER BY sum_timer_wait DESC
LIMIT 20;
















[dba_casulo71@mysql-prod-db1-replica]> SELECT * FROM performance_schema.replication_applier_status_by_worker\G
*************************** 1. row ***************************
                                           CHANNEL_NAME: 
                                              WORKER_ID: 1
                                              THREAD_ID: 46
                                          SERVICE_STATE: ON
                                      LAST_ERROR_NUMBER: 0
                                     LAST_ERROR_MESSAGE: 
                                   LAST_ERROR_TIMESTAMP: 0000-00-00 00:00:00.000000
                               LAST_APPLIED_TRANSACTION: 5afdc24b-bf77-11f0-b5d9-42010a6e5ec9:303264301
     LAST_APPLIED_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP: 2026-09-16 04:38:40.279644
    LAST_APPLIED_TRANSACTION_IMMEDIATE_COMMIT_TIMESTAMP: 2026-09-16 04:38:40.279644
         LAST_APPLIED_TRANSACTION_START_APPLY_TIMESTAMP: 2026-09-16 04:38:40.282290
           LAST_APPLIED_TRANSACTION_END_APPLY_TIMESTAMP: 2026-09-16 04:38:40.283878
                                   APPLYING_TRANSACTION: 5afdc24b-bf77-11f0-b5d9-42010a6e5ec9:303264302
         APPLYING_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP: 2026-09-16 04:38:41.884315
        APPLYING_TRANSACTION_IMMEDIATE_COMMIT_TIMESTAMP: 2026-09-16 04:38:41.884315
             APPLYING_TRANSACTION_START_APPLY_TIMESTAMP: 2026-09-16 04:58:34.246959
                 LAST_APPLIED_TRANSACTION_RETRIES_COUNT: 0
   LAST_APPLIED_TRANSACTION_LAST_TRANSIENT_ERROR_NUMBER: 0
  LAST_APPLIED_TRANSACTION_LAST_TRANSIENT_ERROR_MESSAGE: 
LAST_APPLIED_TRANSACTION_LAST_TRANSIENT_ERROR_TIMESTAMP: 0000-00-00 00:00:00.000000
                     APPLYING_TRANSACTION_RETRIES_COUNT: 0
       APPLYING_TRANSACTION_LAST_TRANSIENT_ERROR_NUMBER: 0
      APPLYING_TRANSACTION_LAST_TRANSIENT_ERROR_MESSAGE: 
    APPLYING_TRANSACTION_LAST_TRANSIENT_ERROR_TIMESTAMP: 0000-00-00 00:00:00.000000
*************************** 2. row ***************************
                                           CHANNEL_NAME: 
                                              WORKER_ID: 2
                                              THREAD_ID: 47
                                          SERVICE_STATE: ON
                                      LAST_ERROR_NUMBER: 0
                                     LAST_ERROR_MESSAGE: 
                                   LAST_ERROR_TIMESTAMP: 0000-00-00 00:00:00.000000
                               LAST_APPLIED_TRANSACTION: 5afdc24b-bf77-11f0-b5d9-42010a6e5ec9:303264242
     LAST_APPLIED_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP: 2026-09-16 04:38:02.491841
    LAST_APPLIED_TRANSACTION_IMMEDIATE_COMMIT_TIMESTAMP: 2026-09-16 04:38:02.491841
         LAST_APPLIED_TRANSACTION_START_APPLY_TIMESTAMP: 2026-09-16 04:38:02.494600
           LAST_APPLIED_TRANSACTION_END_APPLY_TIMESTAMP: 2026-09-16 04:38:02.496355
                                   APPLYING_TRANSACTION: 
         APPLYING_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP: 0000-00-00 00:00:00.000000
        APPLYING_TRANSACTION_IMMEDIATE_COMMIT_TIMESTAMP: 0000-00-00 00:00:00.000000
             APPLYING_TRANSACTION_START_APPLY_TIMESTAMP: 0000-00-00 00:00:00.000000
                 LAST_APPLIED_TRANSACTION_RETRIES_COUNT: 0
   LAST_APPLIED_TRANSACTION_LAST_TRANSIENT_ERROR_NUMBER: 0
  LAST_APPLIED_TRANSACTION_LAST_TRANSIENT_ERROR_MESSAGE: 
LAST_APPLIED_TRANSACTION_LAST_TRANSIENT_ERROR_TIMESTAMP: 0000-00-00 00:00:00.000000
                     APPLYING_TRANSACTION_RETRIES_COUNT: 0
       APPLYING_TRANSACTION_LAST_TRANSIENT_ERROR_NUMBER: 0
      APPLYING_TRANSACTION_LAST_TRANSIENT_ERROR_MESSAGE: 
    APPLYING_TRANSACTION_LAST_TRANSIENT_ERROR_TIMESTAMP: 0000-00-00 00:00:00.000000
*************************** 3. row ***************************
                                           CHANNEL_NAME: 
                                              WORKER_ID: 3
                                              THREAD_ID: 50
                                          SERVICE_STATE: ON
                                      LAST_ERROR_NUMBER: 0
                                     LAST_ERROR_MESSAGE: 
                                   LAST_ERROR_TIMESTAMP: 0000-00-00 00:00:00.000000
                               LAST_APPLIED_TRANSACTION: 5afdc24b-bf77-11f0-b5d9-42010a6e5ec9:303264220
     LAST_APPLIED_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP: 2026-09-16 04:38:02.203120
    LAST_APPLIED_TRANSACTION_IMMEDIATE_COMMIT_TIMESTAMP: 2026-09-16 04:38:02.203120
         LAST_APPLIED_TRANSACTION_START_APPLY_TIMESTAMP: 2026-09-16 04:38:02.207471
           LAST_APPLIED_TRANSACTION_END_APPLY_TIMESTAMP: 2026-09-16 04:38:02.210569
                                   APPLYING_TRANSACTION: 
         APPLYING_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP: 0000-00-00 00:00:00.000000
        APPLYING_TRANSACTION_IMMEDIATE_COMMIT_TIMESTAMP: 0000-00-00 00:00:00.000000
             APPLYING_TRANSACTION_START_APPLY_TIMESTAMP: 0000-00-00 00:00:00.000000
                 LAST_APPLIED_TRANSACTION_RETRIES_COUNT: 0
   LAST_APPLIED_TRANSACTION_LAST_TRANSIENT_ERROR_NUMBER: 0
  LAST_APPLIED_TRANSACTION_LAST_TRANSIENT_ERROR_MESSAGE: 
LAST_APPLIED_TRANSACTION_LAST_TRANSIENT_ERROR_TIMESTAMP: 0000-00-00 00:00:00.000000
                     APPLYING_TRANSACTION_RETRIES_COUNT: 0
       APPLYING_TRANSACTION_LAST_TRANSIENT_ERROR_NUMBER: 0
      APPLYING_TRANSACTION_LAST_TRANSIENT_ERROR_MESSAGE: 
    APPLYING_TRANSACTION_LAST_TRANSIENT_ERROR_TIMESTAMP: 0000-00-00 00:00:00.000000
*************************** 4. row ***************************
                                           CHANNEL_NAME: 
                                              WORKER_ID: 4
                                              THREAD_ID: 51
                                          SERVICE_STATE: ON
                                      LAST_ERROR_NUMBER: 0
                                     LAST_ERROR_MESSAGE: 
                                   LAST_ERROR_TIMESTAMP: 0000-00-00 00:00:00.000000
                               LAST_APPLIED_TRANSACTION: 5afdc24b-bf77-11f0-b5d9-42010a6e5ec9:303263807
     LAST_APPLIED_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP: 2026-09-16 04:36:03.644117
    LAST_APPLIED_TRANSACTION_IMMEDIATE_COMMIT_TIMESTAMP: 2026-09-16 04:36:03.644117
         LAST_APPLIED_TRANSACTION_START_APPLY_TIMESTAMP: 2026-09-16 04:36:03.648607
           LAST_APPLIED_TRANSACTION_END_APPLY_TIMESTAMP: 2026-09-16 04:36:03.651010
                                   APPLYING_TRANSACTION: 
         APPLYING_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP: 0000-00-00 00:00:00.000000
        APPLYING_TRANSACTION_IMMEDIATE_COMMIT_TIMESTAMP: 0000-00-00 00:00:00.000000
             APPLYING_TRANSACTION_START_APPLY_TIMESTAMP: 0000-00-00 00:00:00.000000
                 LAST_APPLIED_TRANSACTION_RETRIES_COUNT: 0
   LAST_APPLIED_TRANSACTION_LAST_TRANSIENT_ERROR_NUMBER: 0
  LAST_APPLIED_TRANSACTION_LAST_TRANSIENT_ERROR_MESSAGE: 
LAST_APPLIED_TRANSACTION_LAST_TRANSIENT_ERROR_TIMESTAMP: 0000-00-00 00:00:00.000000
                     APPLYING_TRANSACTION_RETRIES_COUNT: 0
       APPLYING_TRANSACTION_LAST_TRANSIENT_ERROR_NUMBER: 0
      APPLYING_TRANSACTION_LAST_TRANSIENT_ERROR_MESSAGE: 
    APPLYING_TRANSACTION_LAST_TRANSIENT_ERROR_TIMESTAMP: 0000-00-00 00:00:00.000000
4 rows in set (0.01 sec)


[dba_casulo71@mysql-prod-db1-replica]> SELECT trx_id, trx_started, trx_state, trx_rows_modified, trx_query
    -> FROM information_schema.innodb_trx\G
*************************** 1. row ***************************
           trx_id: 754852184
      trx_started: 2026-09-16 07:58:34
        trx_state: RUNNING
trx_rows_modified: 27035844
        trx_query: NULL


Verificando lock contention:

SELECT * FROM performance_schema.data_lock_waits\G



[dba_casulo71@mysql-prod-db1-replica]> SELECT * FROM performance_schema.data_lock_waits\G
Empty set (1.15 sec)


[dba_casulo71@mysql-prod-db1-replica]> SELECT ENGINE_TRANSACTION_ID, OBJECT_SCHEMA, OBJECT_NAME, LOCK_TYPE, LOCK_MODE, LOCK_STATUS, LOCK_DATA
    -> FROM performance_schema.data_locks
    -> WHERE ENGINE_TRANSACTION_ID = 754852184
    -> LIMIT 20;
+-----------------------+---------------+-------------------------+-----------+---------------+-------------+-----------+
| ENGINE_TRANSACTION_ID | OBJECT_SCHEMA | OBJECT_NAME             | LOCK_TYPE | LOCK_MODE     | LOCK_STATUS | LOCK_DATA |
+-----------------------+---------------+-------------------------+-----------+---------------+-------------+-----------+
|             754852184 | play_db       | etapa                   | TABLE     | IS            | GRANTED     | NULL      |
|             754852184 | play_db       | venda_estoque_cancelado | TABLE     | IX            | GRANTED     | NULL      |
|             754852184 | play_db       | situacao                | TABLE     | IS            | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | TABLE     | IX            | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | RECORD    | X,REC_NOT_GAP | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | RECORD    | X,REC_NOT_GAP | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | RECORD    | X,REC_NOT_GAP | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | RECORD    | X,REC_NOT_GAP | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | RECORD    | X,REC_NOT_GAP | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | RECORD    | X,REC_NOT_GAP | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | RECORD    | X,REC_NOT_GAP | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | RECORD    | X,REC_NOT_GAP | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | RECORD    | X,REC_NOT_GAP | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | RECORD    | X,REC_NOT_GAP | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | RECORD    | X,REC_NOT_GAP | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | RECORD    | X,REC_NOT_GAP | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | RECORD    | X,REC_NOT_GAP | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | RECORD    | X,REC_NOT_GAP | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | RECORD    | X,REC_NOT_GAP | GRANTED     | NULL      |
|             754852184 | play_db       | venda                   | RECORD    | X,REC_NOT_GAP | GRANTED     | NULL      |
+-----------------------+---------------+-------------------------+-----------+---------------+-------------+-----------+





show engine innodb status

TRANSACTIONS
------------
Trx id counter 754855358
Purge done for trx's n:o < 754855358 undo n:o < 0 state: running but idle
History list length 3
LIST OF TRANSACTIONS FOR EACH SESSION:
---TRANSACTION 372326141013648, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141008104, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141006520, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141019192, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141044536, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141036616, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141027112, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141021568, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141020776, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141048496, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141011272, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141042952, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141012064, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141034240, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141024736, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141025528, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141016024, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141014440, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141015232, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141023944, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141022360, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141023152, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141012856, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141010480, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141009688, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141008896, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141007312, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141005728, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141004936, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 372326141003352, not started
0 lock struct(s), heap size 1128, 0 row lock(s)
---TRANSACTION 754852184, ACTIVE 4248 sec starting index read
mysql tables in use 4, locked 4
1915854 lock struct(s), heap size 201220216, 28963957 row lock(s), undo log entries 28963789
MySQL thread id 7, OS thread handle 139472595998464, query id 249729348 Applying batch of row changes (update)
--------


[dba_casulo71@mysql-prod-db1-replica]> SHOW FULL PROCESSLIST;
+--------+--------------------------+-------------------+---------+---------+---------+----------------------------------------------------+-----------------------+
| Id     | User                     | Host              | db      | Command | Time    | State                                              | Info                  |
+--------+--------------------------+-------------------+---------+---------+---------+----------------------------------------------------+-----------------------+
|      5 | system user              | connecting host   | NULL    | Connect | 4676193 | Waiting for source to send event                   | NULL                  |
|      6 | system user              |                   | NULL    | Query   |       0 | Waiting for Replica Workers to free pending events | NULL                  |
|      7 | system user              |                   | play_db | Query   |   18975 | Applying batch of row changes (update)             | NULL                  |
|      8 | system user              |                   | NULL    | Query   |    5583 | Waiting for an event from Coordinator              | NULL                  |
|     11 | system user              |                   | NULL    | Query   |    5583 | Waiting for an event from Coordinator              | NULL                  |
|     12 | system user              |                   | NULL    | Query   |    5702 | Waiting for an event from Coordinator              | NULL                  |
| 632645 | metrics_exporter_service | 10.36.4.174:48528 | play_db | Sleep   |       2 |                                                    | NULL                  |
| 632649 | metrics_exporter_service | 10.36.4.174:55626 | play_db | Sleep   |       2 |                                                    | NULL                  |
| 661861 | metrics_exporter_service | 10.36.4.174:37428 | play_db | Sleep   |       2 |                                                    | NULL                  |
| 661862 | metrics_exporter_service | 10.36.4.174:37420 | play_db | Sleep   |       2 |                                                    | NULL                  |
| 702137 | root                     | 127.0.0.1:50522   | NULL    | Sleep   |       0 |                                                    | NULL                  |
| 702155 | root                     | 127.0.0.1:50680   | NULL    | Sleep   |       2 |                                                    | NULL                  |
| 702164 | root                     | 127.0.0.1:34510   | mysql   | Sleep   |      11 |                                                    | NULL                  |
| 713757 | customer_apiv2           | 10.10.0.20:33362  | play_db | Sleep   |       1 |                                                    | NULL                  |
| 713758 | customer_apiv2           | 10.10.0.20:45398  | play_db | Sleep   |       8 |                                                    | NULL                  |
| 713979 | customer_apiv2           | 10.10.0.20:45560  | play_db | Sleep   |       1 |                                                    | NULL                  |
| 714050 | customer_apiv2           | 10.10.0.20:54318  | play_db | Sleep   |   28626 |                                                    | NULL                  |
| 718676 | customer_apiv2           | 10.10.0.20:48068  | play_db | Sleep   |       8 |                                                    | NULL                  |
| 718825 | customer_apiv2           | 10.10.0.20:41086  | play_db | Sleep   |      38 |                                                    | NULL                  |
| 719063 | customer_apiv2           | 10.10.0.20:33070  | play_db | Sleep   |      24 |                                                    | NULL                  |
| 719236 | customer_apiv2           | 10.10.0.20:60102  | play_db | Sleep   |      14 |                                                    | NULL                  |
| 719961 | customer_apiv2           | 10.10.0.20:42438  | play_db | Sleep   |   26179 |                                                    | NULL                  |
| 721872 | customer_apiv2           | 10.10.0.20:34594  | play_db | Sleep   |      24 |                                                    | NULL                  |
| 722071 | customer_apiv2           | 10.10.0.20:40314  | play_db | Sleep   |       1 |                                                    | NULL                  |
| 722259 | customer_apiv2           | 10.10.0.20:47884  | play_db | Sleep   |      38 |                                                    | NULL                  |
| 722807 | customer_apiv2           | 10.10.0.20:55012  | play_db | Sleep   |      13 |                                                    | NULL                  |
| 723620 | customer_apiv2           | 10.10.0.20:42244  | play_db | Sleep   |       1 |                                                    | NULL                  |
| 728118 | customer_apiv2           | 10.10.0.20:55368  | play_db | Sleep   |   16438 |                                                    | NULL                  |
| 728119 | customer_apiv2           | 10.10.0.20:55370  | play_db | Sleep   |   16438 |                                                    | NULL                  |
| 729996 | root                     | 127.0.0.1:50478   | NULL    | Sleep   |     329 |                                                    | NULL                  |
| 730084 | dba_casulo71             | 10.10.0.33:48750  | play_db | Query   |       0 | init                                               | SHOW FULL PROCESSLIST |
| 730290 | root                     | 127.0.0.1:57772   | NULL    | Sleep   |       2 |                                                    | NULL                  |
| 730291 | root                     | 127.0.0.1:57776   | NULL    | Sleep   |     241 |                                                    | NULL                  |
| 730292 | root                     | 127.0.0.1:46916   | NULL    | Sleep   |       2 |                                                    | NULL                  |
| 730313 | root                     | 127.0.0.1:34554   | NULL    | Sleep   |       2 |                                                    | NULL                  |
| 730314 | root                     | 127.0.0.1:38538   | NULL    | Sleep   |       2 |                                                    | NULL                  |
+--------+--------------------------+-------------------+---------+---------+---------+----------------------------------------------------+-----------------------+


[dba_casulo71@mysql-prod-db1-replica]> SELECT * FROM performance_schema.metadata_locks
    -> WHERE OBJECT_SCHEMA = 'play_db';
+-------------+---------------+-------------------------+-------------+-----------------------+--------------+---------------+-------------+--------------+-----------------+----------------+
| OBJECT_TYPE | OBJECT_SCHEMA | OBJECT_NAME             | COLUMN_NAME | OBJECT_INSTANCE_BEGIN | LOCK_TYPE    | LOCK_DURATION | LOCK_STATUS | SOURCE       | OWNER_THREAD_ID | OWNER_EVENT_ID |
+-------------+---------------+-------------------------+-------------+-----------------------+--------------+---------------+-------------+--------------+-----------------+----------------+
| TABLE       | play_db       | venda_estoque_cancelado | NULL        |        90851527496304 | SHARED_WRITE | TRANSACTION   | GRANTED     | table.h:3039 |              46 |      116624224 |
| TABLE       | play_db       | cliente_detalhe         | NULL        |        90853066307840 | SHARED_WRITE | TRANSACTION   | GRANTED     | table.h:3039 |              46 |      116624224 |
| TABLE       | play_db       | certificado             | NULL        |        90853339038976 | SHARED_WRITE | TRANSACTION   | GRANTED     | table.h:3039 |              46 |      116624224 |
| TABLE       | play_db       | venda                   | NULL        |        90851528247728 | SHARED_WRITE | TRANSACTION   | GRANTED     | table.h:3039 |              46 |      116624224 |
+-------------+---------------+-------------------------+-------------+-----------------------+--------------+---------------+-------------+--------------+-----------------+----------------+


Quer que eu te ajude a montar a query para identificar, no binlog do primário, qual conexão/usuário gerou essa transação (via mysqlbinlog no arquivo próximo ao GTID 303264302), pra você rastrear a origem do job?
Sim, quero.


[dba_casulo71@mysql-prod-db1]> SHOW VARIABLES LIKE 'binlog_rows_query_log_events';
+------------------------------+-------+
| Variable_name                | Value |
+------------------------------+-------+
| binlog_rows_query_log_events | OFF   |
+------------------------------+-------+


[dba_casulo71@mysql-prod-db1-replica]> SHOW VARIABLES LIKE 'binlog_rows_query_log_events';
+------------------------------+-------+
| Variable_name                | Value |
+------------------------------+-------+
| binlog_rows_query_log_events | OFF   |
+------------------------------+-------+


Peguei essa consulta no Query Insights:

UPDATE
  `play_db` . `venda`
SET
  `data_atualizacao` = `data_atualizacao`
WHERE
  `id` >= ?
  AND `id` <= ?




[dba_casulo71@mysql-prod-db1]> SHOW VARIABLES LIKE 'slow_query_log';
+----------------+-------+
| Variable_name  | Value |
+----------------+-------+
| slow_query_log | OFF   |
+----------------+-------+


[dba_casulo71@mysql-prod-db1]> SHOW VARIABLES LIKE 'long_query_time';
+-----------------+-----------+
| Variable_name   | Value     |
+-----------------+-----------+
| long_query_time | 10.000000 |
+-----------------+-----------+


=====================================================


-------------------------------------------------------------
-- Exemplo de padrão de batching

UPDATE play_db.venda SET data_atualizacao = data_atualizacao WHERE id >= 77442364 AND id <= 77467363;


SET @start_id = 77442364;
SET @batch_size = 5000;
SET @max_id = 77467363;

REPEAT
  UPDATE play_db.venda
  SET data_atualizacao = data_atualizacao
  WHERE id BETWEEN @start_id AND @start_id + @batch_size - 1;
  COMMIT;
  SELECT SLEEP(5);
  SET @start_id = @start_id + @batch_size;
UNTIL @start_id > @max_id
END REPEAT;
-------------------------------------------------------------


Habilitar observabilidade

-- No primário
SET GLOBAL binlog_rows_query_log_events = ON;  -- dinâmica, sem restart
SET GLOBAL slow_query_log = ON;
SET GLOBAL long_query_time = 5;  -- ajuste conforme volume normal de queries




-- Procedure
DELIMITER $$

CREATE PROCEDURE play_db.sp_lote_atualiza_venda(
    IN p_start_id BIGINT,
    IN p_max_id BIGINT,
    IN p_batch_size INT,
    IN p_sleep_seconds DECIMAL(5,2)
)
BEGIN
    DECLARE v_start_id BIGINT DEFAULT p_start_id;

    REPEAT
        UPDATE play_db.venda
        SET data_atualizacao = data_atualizacao
        WHERE id BETWEEN v_start_id AND v_start_id + p_batch_size - 1;

        SELECT SLEEP(p_sleep_seconds);
        SET v_start_id = v_start_id + p_batch_size;
    UNTIL v_start_id > p_max_id
    END REPEAT;
END$$

DELIMITER ;

-- Executar:
CALL play_db.sp_lote_atualiza_venda(77442364, 77467363, 5000, 1);

-- Depois de usar, se quiser remover:
DROP PROCEDURE play_db.sp_lote_atualiza_venda;

