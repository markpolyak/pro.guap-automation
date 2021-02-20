import logging
import argparse
import requests
import getpass
import os
import re

import json


# logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
# enable logging
logger = logging.getLogger(__name__)


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
    parser.add_argument(
        '-o', '--output', dest='output_dir',
        action='store',
        default=os.path.abspath(os.path.curdir),
        help="output directory",
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


def process_reports(sess, task, output_dir, dry_run):
    # get reports
    # process_reports(sess, tasks[task_id], params.output_dir, params.dry_run)
    res = sess.post(f"https://pro.guap.ru/gettask/{task['id']}", json={"task_id": task['id']})
    # reports_per_group = {}
    logger.info("Reports will be saved to '%s'", output_dir)
    saved_reports_count = 0
    for report in res.json()['reports']['reports']:
        # if report['group_num'] not in reports_per_group:
        #     reports_per_group[report['group_num']] = {}
        # if report['user_fio'] not in reports_per_group[report['group_num']]:
        #     reports_per_group[report['group_num']][report['user_fio']] = {}
        if not report['filelink']:
            continue
        path = os.path.join(output_dir, task['subject_name'][0], report['group_num'], task['name'])
        os.makedirs(path, exist_ok=True)
        report_url = f"https://pro.guap.ru{report['filelink']}"
        res = sess.get(report_url)
        original_filename = re.findall('filename=(.+)', res.headers.get('content-disposition', ''))
        if len(original_filename) > 0:
            original_filename = original_filename[0]
        else:
            original_filename = report_url.split('/')[-1]
        original_extension = os.path.splitext(original_filename)[1].strip('"')
        new_filename = os.path.join(path, f"{report['user_fio']} [{report['status_name']}]{original_extension}")
        if not dry_run:
            with open(new_filename, 'wb') as f:
                f.write(res.content)
        print(f"{report['user_fio']} ({report['group_num']}) [{report['status_name']}]: {report_url} -> {new_filename}")
        saved_reports_count += 1
    logger.info("Total %s reports were downloaded", saved_reports_count)
    if saved_reports_count == 0:
        logger.info("No downloadable reports were found for this task")



def main():
    # parse command line parameters
    params = _parse_args()
    logging.basicConfig(format='%(levelname)s:%(message)s', level=params.loglevel)
    if params.dry_run:
        logger.info("Dry-run mode. No files will be saved to disk, although reports will still be downloaded")
    sess = requests.Session()
    if params.username:
        password = getpass.getpass(prompt=f"Password [{params.username}@pro.guap.ru]: ")
        # get authorization form (without it next post request with correct username and password fails)
        res = sess.get('https://pro.guap.ru/user/login')
        # authorize
        res = sess.post('https://pro.guap.ru/user/login_check', data={'_username': params.username, '_password': password})
        # print(res.status_code)
        # print(res.text)
        # print(sess.cookies)
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
        res = sess.get(f'https://pro.guap.ru/goswitch?_want_to_be_this_user={params.impersonate}')
        if res.status_code != 200:
            logger.error("Unable to impersonate user '%s'. Server response: %s (%d)", params.impersonate, res.reason, res.status_code)
    # open tasks page in order to locate a user_id in HTML source code
    res = sess.get('https://pro.guap.ru/inside#tasks')
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
    # print(json.dumps(groups_by_task, sort_keys=True, indent=4))
    tasks = {}
    task_choices = []
    for task in res.json()['tasks']:
        if task['hasReports']:
            subject = task['subject_name'][0] # don't bother with different subject names for different groups, just use the first one
            # print(task)
            # groups = ", ".join([groups_by_task[str(task['subject'][idx])][str(group_id)] for idx, group_id in enumerate(task['groups'])])
            groups = ", ".join([groups_by_task[str(group_id)] for idx, group_id in enumerate(task['groups'])])
            task_choices.append(task['id'])
        tasks[task['id']] = task
    if params.batch:
        for task_id in tasks:
            if task['hasReports']:
                logger.info("Processing reports for task '%s: %s'", tasks[task_id]['subject_name'][0], tasks[task_id]['name'])
                process_reports(sess, tasks[task_id], params.output_dir, params.dry_run)
    else:
        print("\n".join([
            f"{task['id']}: {subject}: {task['name']} ({groups}) [Студентов: {task['count']}; принято: {task['doneWork']}, ожидают: {task['await']}]" for task in res.json()['tasks'] if task['hasReports']
        ]))
        print()
        task_id = get_user_choice("Укажите идентификатор задания: ", task_choices)
        # print(f"Selected task is '{tasks[task_id]['subject_name'][0]}: {tasks[task_id]['name']}'")
        logger.info("Processing reports for task '%s: %s'", tasks[task_id]['subject_name'][0], tasks[task_id]['name'])
        process_reports(sess, tasks[task_id], params.output_dir, params.dry_run)
    
    # общие словари:
    # res = sess.post('https://pro.guap.ru/gettasksdictionaries/', json={"iduser":440})
    # задания за конкретный семестр:
    # res = sess.post('https://pro.guap.ru/gettasks/', json={"iduser":440, "semester":16})
    # конкретное задание:
    # res = sess.post('https://pro.guap.ru/gettask/61088', json={"task_id":61088})


if __name__ == '__main__':
    main()
