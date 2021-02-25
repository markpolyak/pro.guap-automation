import logging
import argparse
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import getpass
import os
import re

import json


# logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
# enable logging
logger = logging.getLogger(__name__)


headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
    "Accept-Encoding": "*",
    "Connection": "keep-alive"
}


def _parse_args():
    """
    Internal function intended to parse command line arguments
    """
    parser = argparse.ArgumentParser(
        description="Get data from pro.guap.ru")
    # arguments
    parser.add_argument(
        '-u', '--user', dest='username',
        action='store',
        help="username for authentication at pro.guap.ru",
    )
    parser.add_argument(
        '-c', '--cookie', dest='cookie',
        action='store',
        help="PHPSESSID cookie value for authentication at pro.guap.ru",
    )
    parser.add_argument(
        '-i', '--as', '--impersonate', dest='impersonate',
        action='store',
        help="impersonate another user (requires admin account)",
    )
    parser.add_argument(
        '-s', '--semester', dest='semester',
        action='store',
        help="semester id",
    )
    parser.add_argument(
        '-b', '--batch', dest='batch',
        action='store_true',
        help="silently process all tasks",
    )
    # parser.add_argument(
    #     '--filter', dest='status_filter',
    #     action='store', nargs='+', default=['accepted', 'awaiting'],
    #     choices=['rejected', 'accepted', 'awaiting'],
    #     help="save only reports with given status (by default rejected reports are not saved)",
    # )
    parser.add_argument(
        '--status', dest='status_filter',
        action='store', nargs='+', default=['accepted', 'awaiting'],
        choices=['rejected', 'accepted', 'awaiting'],
        help="save reports with desired statuses only (by default rejected reports are ignored)",
    )
    parser.add_argument(
        '-g', '--group', dest='group_filter',
        action='store', nargs='+', default=None,
        help="save reports from desired student groups only (by default all groups are saved)",
    )
    parser.add_argument(
        '--keep-old', dest='keep_old',
        action='store_true', default=False,
        help="do not overwrite existing files, choose a new name instead",
    )
    parser.add_argument(
        '-o', '--output', '--output-dir', dest='output_dir',
        action='store',
        default=os.path.abspath(os.path.curdir),
        help="output directory",
    )
    parser.add_argument(
        '-l', '--log-file', dest='log_file',
        action='store',
        default='downloads.log',
        help="log file with all downloaded reports",
    )
    parser.add_argument(
        '--dry-run', dest='dry_run',
        action='store_true',
        help="do not save any reports, just print stats to console",
    )
    parser.add_argument(
        '-d', '--debug',
        help="Print lots of debugging statements",
        action="store_const", dest="loglevel", const=logging.DEBUG,
        default=logging.WARNING,
    )
    parser.add_argument(
        '-v', '--verbose',
        help="Be verbose",
        action="store_const", dest="loglevel", const=logging.INFO,
    )
    # parser.add_argument(
    #     '--logging-config', dest='logging_config', action='store',
    #     default=os.path.join(os.path.dirname(os.path.realpath(__file__)),
    #                          'logging.yaml'),
    #     help='set logging config file',
    # )
    return parser.parse_args()


def requests_retry_session(
    retries=3,
    backoff_factor=0.3,
    status_forcelist=(500, 502, 504),
    session=None,
):
    """
    Build a retry session for requests
    """
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def get_user_choice(text=None, allowed_choices=None):
    user_choice = None
    user_choice_num = None
    if allowed_choices:
        while True:
            user_choice = input(text)
            try:
                user_choice_num = int(user_choice)
            except ValueError:
                logger.debug("Value '%s' is not a number", user_choice)
                pass
            if not allowed_choices or user_choice in allowed_choices:
                return user_choice
            elif user_choice_num in allowed_choices:
                return user_choice_num
            print(f"Please, choose one of the following values: {allowed_choices} or press Ctrl+C to exit")


def process_reports(
    sess, task, output_dir, status_filter, group_filter=None, 
    dry_run=False, keep_old=False, downloaded_reports={}, log_file=None
):
    # get reports
    res = sess.post(f"https://pro.guap.ru/gettask/{task['id']}", json={"task_id": task['id']})
    # remove all non-alphanumeric characters from task name (see https://stackoverflow.com/a/13593932)
    task_name = re.sub('[^\w\-_\. ]', '_', task['name'])
    # remove trailing whitespaces and truncate to 255 characters in order to support Windows
    task_name = task_name.strip()[:255]
    logger.info("Reports for task '%s' will be saved to '%s'", task_name, output_dir)
    saved_reports_count = 0
    for report in res.json()['reports']['reports']:
        # skip reports without a filelink
        if not report['filelink']: #  or (ignore_rejected and report['status'] == '3')
            logger.debug("Report from '%s' (%s) has no file link and will be skipped (nothing to download)", report['user_fio'], report['group_num'])
            continue
        # skip reports that were already downloaded
        if report['filelink'] in downloaded_reports:
            logger.debug("Report '%s' already downloaded to '%s' and will be skipped", report['filelink'], downloaded_reports[report['filelink']])
            continue
        # skip reports from unwanted groups
        if group_filter and report['group_num'] not in group_filter:
            logger.debug("Report from group '%s' (%s) is ignored by filter", report['group_num'], report['user_fio'])
            continue
        # skip reports with unwanted status
        if (
            (report['status'] == '1' and 'awaiting' not in status_filter) # and report['status_name'] == 'ожидает проверки'
            or (report['status'] == '2' and 'accepted' not in status_filter) # and report['status_name'] == 'принят'
            or (report['status'] == '3' and 'rejected' not in status_filter) # and report['status_name'] == 'не принят'
        ):
            logger.debug("Report with status '%s' from '%s' (%s) is ignored by filter", report['status_name'], report['user_fio'], report['group_num'])
            continue
        # build full path and create missing subdirs if any
        path = os.path.join(output_dir, task['subject_name'][0], report['group_num'], task_name)
        os.makedirs(path, exist_ok=True)
        # process report
        report_url = f"https://pro.guap.ru{report['filelink']}"
        res = sess.get(report_url, headers=headers)
        original_filename = re.findall('filename=(.+)', res.headers.get('content-disposition', ''))
        if len(original_filename) > 0:
            original_filename = original_filename[0]
        else:
            original_filename = report_url.split('/')[-1]
        original_extension = os.path.splitext(original_filename)[1].strip('"')
        new_filename = os.path.join(path, f"{report['user_fio']} [{report['status_name']}]{original_extension}")
        if keep_old:
            filename_suffix_id = 1
            while os.path.isfile(new_filename):
                new_filename_upd = os.path.join(path, f"{report['user_fio']} [{report['status_name']}]({filename_suffix_id}){original_extension}")
                logger.warning("File '%s' already exists. Will attempt to save file as '%s'", new_filename, new_filename_upd)
                new_filename = new_filename_upd
                filename_suffix_id += 1
        if not dry_run:
            with open(new_filename, 'wb') as f:
                f.write(res.content)
        print(f"{report['user_fio']} ({report['group_num']}) [{report['status_name']}]: {report_url} -> {new_filename}")
        if log_file:
            log_file.write(f"{report['filelink']}\t{new_filename}\n")
        saved_reports_count += 1
    logger.info("Downloaded %s reports for %s: %s", saved_reports_count, task['subject_name'][0], task_name)
    if saved_reports_count == 0:
        logger.info("No downloadable reports were found for this task")
    return saved_reports_count



def main():
    # parse command line parameters
    params = _parse_args()
    logging.basicConfig(format='%(levelname)s:%(message)s', level=params.loglevel)
    if params.dry_run:
        logger.info("Dry-run mode. No files will be saved to disk, although reports will still be downloaded")
    # load list of previously downloaded reports
    downloaded_reports = {}
    try:
        with open(params.log_file) as f:
            for line in f:
                line_items = line.strip().split('\t')
                downloaded_reports[line_items[0]] = line_items[1]
            # downloaded_reports = {line.split('\t')[].strip() for line in f}
    except OSError as e:
        logger.warning("Unable to open downloads log file '%s'. No information about predownloaded reports is found", params.log_file)
        logger.debug(e)
    logger.info("Total %s predownloaded reports were found", len(downloaded_reports))
    # authenticate
    sess = requests_retry_session()
    if params.username:
        password = getpass.getpass(prompt=f"Password [{params.username}@pro.guap.ru]: ")
        # get authorization form (without it next post request with correct username and password fails)
        res = sess.get('https://pro.guap.ru/user/login', headers=headers)
        # authorize
        res = sess.post('https://pro.guap.ru/user/login_check', data={'_username': params.username, '_password': password}, headers=headers)
        if res.status_code != 200:
            logger.error("Unable to authenticate user '%s'", params.username)
            exit(1)
    elif params.cookie:
        cookie_obj = requests.cookies.create_cookie(
            domain='pro.guap.ru',
            name='PHPSESSID',
            value=params.cookie)
        sess.cookies.set_cookie(cookie_obj)
    else:
        logger.error("No authentication details were provided. Please, specify a user name or a PHPSESSID cookie value for pro.guap.ru as a command line parameter for this script")
        exit(1)
    # impersonate: https://pro.guap.ru/goswitch?_want_to_be_this_user=Polyak_MD
    if params.impersonate:
        logger.info("Trying to impersonate user '%s'", params.impersonate)
        res = sess.get(f'https://pro.guap.ru/goswitch?_want_to_be_this_user={params.impersonate}', headers=headers)
        if res.status_code != 200:
            logger.error("Unable to impersonate user '%s'. Server response: %s (%d)", params.impersonate, res.reason, res.status_code)
    # open tasks page in order to locate a user_id in HTML source code
    res = sess.get('https://pro.guap.ru/inside#tasks', headers=headers)
    if res.status_code != 200:
        logger.error("Unable to load page '%s'", 'https://pro.guap.ru/inside#tasks')
        exit(1)
    # extract user_id
    try:
        user_id = int(res.text.split("user_id")[1].split(',')[0].strip(":\""))
    except (ValueError, IndexError):
        logger.error("Unable to locate 'user_id' in page source")
        logger.debug("Page source: %s", res.text)
        exit(1)
    # get dictionaries with semester choices (ids)
    res = sess.post('https://pro.guap.ru/gettasksdictionaries/', json={"iduser": user_id})
    semester_ids = []
    # semester_names = []
    semesters = {}
    # [(semester_ids.append(i['id']), semester_names.append(i['name'])) for i in res.json()['dictionaries']['semester']]
    # [print(f"{i['id']}: {i['name']}") for i in res.json()['dictionaries']['semester']]
    for sem in res.json()['dictionaries']['semester']:
        # print(f"{sem['id']}: {sem['name']}")
        semester_ids.append(sem['id'])
        # semester_names.append(sem['name'])
        semesters[sem['id']] = sem['name']
    if params.semester in semesters:
        semester_id = params.semester
    else:
        if params.semester:
            logger.error("Semester '%s' not found. Possible values are %s.", params.semester, semester_ids)
        print()
        print("\n".join([f"{sem['id']}: {sem['name']}" for sem in res.json()['dictionaries']['semester']]))
        semester_id = get_user_choice("Укажите идентификатор семестра: ", semester_ids)
        # print(f"Выбран семестр '{semester_names[semester_ids.index(semester_id)]}'")
        # print(f"Выбран семестр '{semesters[semester_id]}'")
    logger.info("Selected semester is '%s'", semesters[semester_id])
    # get tasks
    res = sess.post('https://pro.guap.ru/gettasks/', json={"iduser": user_id, "semester": semester_id})
    # parse group names into a usable dictionary
    # originally groups are sorted per subject id with duplicates
    groups_by_task = {}
    for i in res.json()['dictionaries']['groups']:
        # groups_by_task[i['id']] = {g['id']: g['text'] for g in i['groups']}
        for g in i['groups']:
            if g['id'] not in groups_by_task:
                groups_by_task[g['id']] = g['text']
            elif groups_by_task[g['id']] != g['text']:
                logger.error("Duplicate group id found! $s | $s | $s", i, g, groups_by_task[g['id']])
    # parse tasks
    tasks = {}
    task_choices = []
    for task in res.json()['tasks']:
        if task['hasReports']:
            task_choices.append(task['id'])
        tasks[task['id']] = task
        # add human readable subject name and groups list
        subject = task['subject_name'][0] # don't bother with different subject names for different groups, just use the first one 
        groups = ", ".join([groups_by_task[str(group_id)] for idx, group_id in enumerate(task['groups'])])
        tasks[task['id']]['subject_hr'] = subject
        tasks[task['id']]['groups_hr'] = groups
    # download reports
    downloads_log_file = open(params.log_file, 'a')
    total_saved_reports = 0
    if params.batch:
        for task_id in tasks:
            if task['hasReports']:
                logger.info("Processing reports for task '%s: %s'", tasks[task_id]['subject_name'][0], tasks[task_id]['name'])
                total_saved_reports += process_reports(
                    sess, tasks[task_id], params.output_dir,
                    status_filter=params.status_filter,
                    group_filter=params.group_filter,
                    dry_run=params.dry_run,
                    keep_old=params.keep_old,
                    downloaded_reports=downloaded_reports,
                    log_file=downloads_log_file
                )
    else:
        print("\n".join([
            f"{task['id']}: {task['subject_hr']}: {task['name']} ({task['groups_hr']}) [Студентов: {task['count']}; принято: {task['doneWork']}, ожидают: {task['await']}]" for task in tasks.values() if task['hasReports']
        ]))
        print()
        task_id = get_user_choice("Укажите идентификатор задания: ", task_choices)
        # print(f"Selected task is '{tasks[task_id]['subject_name'][0]}: {tasks[task_id]['name']}'")
        logger.info("Processing reports for task '%s: %s'", tasks[task_id]['subject_hr'], tasks[task_id]['name'])
        total_saved_reports += process_reports(
            sess, tasks[task_id], params.output_dir,
            status_filter=params.status_filter,
            group_filter=params.group_filter,
            dry_run=params.dry_run,
            keep_old=params.keep_old,
            downloaded_reports=downloaded_reports,
            log_file=downloads_log_file
        )
    downloads_log_file.close()
    logger.info("Total of %s new reports were downloaded", total_saved_reports)
    
    # общие словари:
    # res = sess.post('https://pro.guap.ru/gettasksdictionaries/', json={"iduser":440})
    # задания за конкретный семестр:
    # res = sess.post('https://pro.guap.ru/gettasks/', json={"iduser":440, "semester":16})
    # конкретное задание:
    # res = sess.post('https://pro.guap.ru/gettask/61088', json={"task_id":61088})


if __name__ == '__main__':
    main()
