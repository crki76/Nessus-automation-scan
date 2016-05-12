from nessus_scan import *
import ConfigParser


""" Reading config file for scan credendials """
main_dir = os.path.dirname(os.path.dirname(__file__))
config = ConfigParser.ConfigParser()
config.readfp(open(os.path.join(main_dir, 'config')))
del main_dir


url = config.get('config.data', 'url')
user = config.get('config.data', 'user')
passwd = config.get('config.data', 'passwd')
policies_command = config.get('config.data', 'policies_command')
policy_to_test = config.get('config.data', 'policy_to_test')
name = config.get('config.data', 'name')
target = config.get('config.data', 'target')
url_path = config.get('config.data', 'url_path')
zname_issues = config.get('config.data', 'zname_issues')
description = ''
token = ''


print "*************************************************************************************************************"
print "***************************** NESSUS SCAN VULNERABILITIES AUTOMATION ****************************************"
print "*************************************************************************************************************"
print "validating our IP address"
validate_it(target)

print "Checking and deleting previous scans from directory"
check_if_dir_contains_any_scanning_file()

scan_name = create_scan_name(name)
print "The scan has got an unique name ---> %s" % (scan_name)

print "Getting token"
token = get_session_token(url, user, passwd)

print "Finding the proper scan policy"
my_policy_uuid = get_policy(token, policies_command, policy_to_test)
check_if_policy_was_found(my_policy_uuid)

print "Scan will use %s policy" % (policy_to_test)

print "Create a new scan"
my_policy_id = add_new_scan(token, my_policy_uuid, scan_name, description, target, url_path)

print "Launch a new scan"
uuid = launch_my_test(token, my_policy_id)

print "Checking if scan is over"
current_test_status = get_scan_status(token,uuid)
is_over = check_if_scan_is_over(current_test_status)
is_still_working(is_over, token, uuid)

print "Working on exporting the scan result"
scan_id = get_scan_id(token, uuid)
export_file_id = export_scan(token, uuid, 'csv')
exporting_status = export_status(token, export_file_id, scan_id)

print "Working on downloading the scan result"
download_process = download_scan_result(token, export_file_id, scan_name, 'csv', scan_id)
export_file_id = export_scan(token, uuid, 'csv')

print "Process of analyzing of the scan"
read_it = access_file(download_process)
readable_issues = display_issues(read_it, zname_issues)

print "Deleting the current scan from the Nessus tool"
delete_single_scan(token, scan_id)

#print "Deleting file from the local directory"
#delete_file_from_dir(scan_name)



