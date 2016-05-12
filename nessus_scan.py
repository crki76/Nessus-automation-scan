import os
import requests
import json
import time
import csv
import socket

requests.packages.urllib3.disable_warnings()

def get_list_templates_url(url):
    templ_url = 'https://%s/editor/policy/templates' % (url)
    return templ_url


def login_url(url):
     log_url = 'https://%s/session' % (url)
     return log_url


def get_policy(token, policies, test_policy):
    try:
        data = connect_policy(token, policies)
        output = json.loads(data)
        for entry in output['templates']:
            if entry.get('title', None) == test_policy:
                return entry['uuid']
    except:
        raise Exception ("Problem with the output in get_policy(). It does not contains UUID")

def check_if_policy_was_found(policy):
    try:
        if policy == None:
            raise
    except:
        raise Exception ("The policy does not exist")


def validate_it(IP):
    try:
        socket.inet_aton(IP)
    except:
        socket.error
        raise ValueError("Invalid IP format!")


def create_scan_name(name):
    second_part = current_time_date()
    return (name+"_"+second_part)


def add_new_scan(token, uuid, name, description, target, url_path):
    try:

        headers = my_header(token)
        path = "<nessus ip/host name>%s" % (url_path)
        payload = {'uuid': uuid,
                'settings': {
                    'name': name,
                    'description': description,
                    'emails': "<receiver email address>",
                    'text_targets': target}}
        payload = json.dumps(payload)
        session = requests.session()
        r = requests.post(path, payload, headers=headers, verify=False)
        output = json.loads(r.content)
        object = output['scan']
        for i in object:
            if i == "id":
                return object['id']
    except:
        raise Exception


def connect_policy(token, command):
    headers = my_header(token)
    path = "<nessus ip/host name>%s" % (command)
    session = requests.session()
    r = requests.get(path, headers=headers, verify=False)
    return r.content


def get_session_token(url, user, passwd):
    try:

        url_login = login_url(url)
        payload = {"username":user,"password":passwd}
        session = requests.session()
        r = requests.post(url_login, data=payload, verify=False)
        if r.status_code == 200:
            jsonres = r.json()
            token = jsonres.get('token')
            return token
        elif r.status_code == 401:
            raise
        else:
            print "Test failed for incorrect response in get_session_token"
            raise
    except:
        raise Exception ("Exception in get_session_token - invalid CREDENTIALS")


def launch_my_test(token, id):
    try:

        headers = my_header(token)
        path = "<nessus ip/host name>/scans/%s/launch" % (id)
        session = requests.session()
        r = requests.post(path, headers=headers, verify=False)
        output = json.loads(r.content)
        return output['scan_uuid']
    except:
        raise Exception("Exception in launch_my_test. Problem with token or with ID or with the path")


def current_time_date():
    """
    I want to add a date and time to the name of the scan to be more straight forward for a user on Nessus UI
    """
    cas = time.strftime("[time %H-%M-%S]")
    datum = time.strftime("[date %d-%m-%Y]")
    return cas+"_"+datum

def my_header(token):
    headers = {'X-Cookie': 'token={0}'.format(token),
               'content-type': 'application/json'}
    return headers


def access_file(path_of_the_file):
    with open(path_of_the_file) as csvfile:
        reader = csv.DictReader(csvfile)
        issues = []
        for row in reader:
            if row.get('Risk',"None") != "None":
                issues.append(row)
        return issues

def display_issues(collection, known_issues):
    issues_formated=[]
    issue_for_testing = []
    print "************************************************************************************************************"
    print "*************************************** FOUND RISK ISSUES **************************************************"
    print "************************************************************************************************************"
    for row in collection:
            name = row['Name']
            risk = row['Risk']
            host = row['Host']
            protocol = row['Port']
            issues_formated.append("[Risk] ---> "+risk+" [Issue name] ---> "+name+" [Host] ---> "+host+" [Protocol] ---> "+ protocol)
            issue_for_testing.append(name)
    print '\n'.join(issues_formated)
    result = analyzing(issue_for_testing,known_issues)
    if result:
        print result
        print "test fail"
    else:
        print "Test PASSED no new issues found"

def analyzing(issues_for, collection_of_known_issues):
    issues_not_matched = []
    for row in issues_for:
        if row not in collection_of_known_issues:
            issues_not_matched.append(row)


def get_scan_status(token, scan_uuid):
    try:
        headers = my_header(token)
        path = "<nessus ip/host name>/scans/"
        session = requests.session()
        r = requests.get(path, headers=headers, verify=False)
        output = json.loads(r.content)
        for entry in output:
            if entry == "scans":
                for entry in output['scans']:
                    if entry['uuid'] == scan_uuid:
                        return (entry['status'])
    except:
        raise Exception ("Exception in get_scan_status - problem with finding the correct scan")


def check_if_scan_is_over(status):
    if status != 'completed':
        time.sleep(10)
        date_for_log = current_time_date()
        log = date_for_log + " Scan in process. The current status is %s" % (status)
        print (log)
        return "still working"
    else:
        return "finished"

def is_still_working(over, token, uuid):
    while over != "finished":
        current_test_status = get_scan_status(token,uuid)
        over = check_if_scan_is_over(current_test_status)

def export_scan(token, scan_uuid, format):
    try:
        scan_id = get_scan_id(token, scan_uuid)
        headers = my_header(token)
        path = "<nessus ip/host name>/scans/%s" % (scan_id)
        session = requests.session()
        r = requests.get(path, headers=headers, verify=False)
        output = json.loads(r.content)

        for entry in output:
            if entry == "history":
                for entry in output['history']:
                    history_id = (entry['history_id'])
                    payload = {'history_id':history_id,'format': format}
                    path = "<nessus ip/host name>/scans/%s/export" % (scan_id)
                    session = requests.session()
                    payload = json.dumps(payload)
                    r = requests.post(path, payload, headers=headers, verify=False)
                    output = json.loads(r.content)
                    return output['file']
    except:
        raise Exception ("Exception raised - problem with export_scan - scan_id or payload are incorrect")


def get_scan_id(token, scan_uuid):
    try:
        headers = my_header(token)
        path = "<nessus ip/host name>/scans/"
        session = requests.session()
        r = requests.get(path, headers=headers, verify=False)
        output = json.loads(r.content)
        for entry in output:
            if entry == "scans":
                for entry in output['scans']:
                    if (entry['uuid']) == scan_uuid:
                        return (entry['id'])
    except:
        raise Exception ("Exception in get_scan_id(). No such as dict - incorrect uuid")

def export_status(token, file_id, scan_id):
    try:
        headers = my_header(token)
        path = "<nessus ip/host name>/scans/%s/export/%s/status" % (scan_id,file_id)
        session = requests.session()
        r = requests.get(path, headers=headers, verify=False)
        output = json.loads(r.content)
        return output['status']
    except:
        raise Exception

def download_scan_result(token, file_id, name, format, scan_id):
    try:
        local_environment = os.name
        if local_environment is 'nt':
            cur_dir = os.path.dirname(os.path.abspath(__file__))
        else:
            cur_dir = os.path.abspath(os.path.curdir)
        filename = os.path.join(cur_dir, "%s_CSV.%s" % (name, format))

        headers = my_header(token)
        path = "<nessus ip/host name>/scans/%s/export/%s/download" % (scan_id,file_id)
        session = requests.session()
        r = requests.get(path, headers=headers, verify=False)
        x = r.content
        with open(filename, 'w+') as f:
            f.write(x)
            f.close()
            return filename
    except:
        raise Exception ("Not such file or directory")

def delete_single_scan(token, scan_id):
    try:
        headers = my_header(token)
        path = "<nessus ip/host name>/scans/%s" % (scan_id)
        session = requests.session()
        r = requests.delete(path, headers=headers, verify=False)
        if r.status_code == 200:
            double_check = check_if_scan_still_exists(token, scan_id)
            if double_check == True:
                print "Scan was deleted"
            else:
                print "Scan was NOT deleted"
    except:
        raise Exception ("Scan does not exist")


def check_if_scan_still_exists(token, scan_id):
    headers = my_header(token)
    path = "<nessus ip/host name>/scans/%s" % (scan_id)
    session = requests.session()
    r = requests.get(path, headers=headers, verify=False)
    if r.status_code == 200:
        return False
    else:
        return True

def delete_file_from_dir(name):
    """    I want to delete the scan file from the directory at the end of the testing
    It is implemented for Linux at the moment
    """
    try:
        cur_file_dir = os.path.abspath(os.path.curdir)+"/%s" % (name)
        os.remove(cur_file_dir)
    except:
        raise Exception ("Not such as file or directories")


def check_if_dir_contains_any_scanning_file():
    try:
        cur_file_dir = os.path.abspath(os.path.curdir)
        list_of_dir = os.listdir(cur_file_dir)
        if list_of_dir:
            for i in list_of_dir:
                if "auto_scan_Nessus" in i:
                    delete_file_from_dir(i)
                    print "Deleted old scanning result %s" % (i)
        print "There is no any previous scan in this directory"
    except:
        raise Exception ("no such a file or dir")

