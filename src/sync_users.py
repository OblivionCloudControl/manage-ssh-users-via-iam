#!/usr/bin/env python

import grp
import os
import pwd

import boto3
import logging
import sys
from logging.handlers import SysLogHandler


log = logging.getLogger(__name__)

iam = boto3.client('iam')


def setup_logging():
    log.setLevel(logging.DEBUG)

    log_format = 'sync_users - %(levelname)s - %(message)s'
    syslog_formatter = logging.Formatter(log_format)
    stdout_formatter = logging.Formatter('%%(asctime)s - %s' % log_format)

    syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
    stdout_handler = logging.StreamHandler(sys.stdout)

    syslog_handler.setFormatter(syslog_formatter)
    stdout_handler.setFormatter(stdout_formatter)

    log.addHandler(syslog_handler)
    log.addHandler(stdout_handler)


def print_logging(msg):
    log.info(msg)


def list_keys_per_user(**kwargs):

    return [
        iam.get_ssh_public_key(UserName=ssh_public_key['UserName'], SSHPublicKeyId=ssh_public_key['SSHPublicKeyId'],
                               Encoding='SSH')['SSHPublicKey']
        for ssh_public_key in iam.list_ssh_public_keys(**kwargs)['SSHPublicKeys']]


def populate_users(**kwargs):

    return [
        dict({unicode('authorized_keys'): unicode('\n'.join([
            '%s SSHPublicKeyId=%s' % (ssh_key['SSHPublicKeyBody'], ssh_key['SSHPublicKeyId'])
            for ssh_key in list_keys_per_user(UserName=iam_user['UserName'])
            if ssh_key['Status'] == 'Active'
        ])), unicode('ssh_user'): unicode(iam_user['UserName'].lower())}.items() + iam_user.items())
        for iam_user in iam.get_group(**kwargs)['Users']
    ]


def user_exists(username):
    try:
        return pwd.getpwnam(username)
    except KeyError:
        return False


def group_exists(groupname):
    try:
        return grp.getgrnam(groupname)
    except KeyError:
        return False


def create_local_group(groupname):
    try:
        return grp.getgrnam(groupname)
    except KeyError:
        print_logging('Create group %s' % groupname)

        create_group_command = 'groupadd %s' % groupname
        os.system(create_group_command)

        return grp.getgrnam(groupname)


def create_user(username, groupname, rotate_user=False):
    if user_exists(username=username) and rotate_user:
        print_logging('User %s already exists, but not part of group. Rotating user' % username)
        delete_user(username)

    print_logging('Create user %s' % username)
    create_user_command = 'useradd -G %s,wheel -c "%s" -m %s' % (groupname, username, username)
    os.system(create_user_command)

    return user_exists(username=username)


def sync_users(iam_users, groupname, local_group_data):
    iam_usernames = [iam_user['ssh_user'] for iam_user in iam_users]
    print_logging('Got IAM users: %s' % ', '.join(sorted(iam_usernames)))

    gr_name, gr_passwd, gr_gid, gr_mem = local_group_data
    print_logging('Got local users: %s' % ', '.join(sorted(gr_mem)))

    to_remove = [local_user for local_user in gr_mem if local_user not in [iam_user for iam_user in iam_usernames]]
    to_add = [iam_user for iam_user in iam_usernames if iam_user not in [local_user for local_user in gr_mem]]

    for user in to_remove:
        delete_user(username=user)

    for user in to_add:
        create_user(username=user, groupname=groupname, rotate_user=True)

    return to_remove, to_add


def write_ssh_authorized_keys(iam_users):
    for iam_user in iam_users:
        pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell = user_exists(username=iam_user['ssh_user'])

        ssh_dir = os.path.join(pw_dir, '.ssh')
        if not os.path.isdir(ssh_dir):
            os.mkdir(ssh_dir)

        os.chown(ssh_dir, pw_uid, pw_gid)
        os.chmod(ssh_dir, 0700)

        ssh_authorized_keys = os.path.join(ssh_dir, 'authorized_keys')

        print_logging('Writing authorized_keys for user %s' % iam_user['ssh_user'])
        f = open(ssh_authorized_keys, 'w')
        f.write('%s\n' % iam_user['authorized_keys'])
        f.close()

        os.chown(ssh_authorized_keys, pw_uid, pw_gid)
        os.chmod(ssh_authorized_keys, 0700)


def write_sudo_config(groupname):
    sudoers_file = os.path.join('/etc/sudoers.d/', groupname)

    print_logging('Writing sudoers config')
    f = open(sudoers_file, 'w')
    f.write('%%%s ALL=(ALL) NOPASSWD:ALL' % groupname)
    f.close()

    os.chown(sudoers_file, 0, 0)
    os.chmod(sudoers_file, 600)


def delete_sudo_config(groupname):
    sudoers_file = os.path.join('/etc/sudoers.d/', groupname)

    return True if not os.path.exists(sudoers_file) else os.remove(sudoers_file)


def delete_user(username):
    print_logging('Delete user %s' % username)

    if username in ('root', 'ec2-user', 'centos', 'ubuntu'):
        print_logging('Cannot delete user')
        return False

    delete_user_command = 'userdel -r %s' % username
    os.system(delete_user_command)

    return True


def delete_users(groupname):
    groupdata = group_exists(groupname)

    if not groupdata:
        return True

    gr_name, gr_passwd, gr_gid, gr_mem = groupdata

    for member in gr_mem:
        delete_user(member)


def format_groupname(groupname):
    return ''.join(map(lambda x: x if (x.isupper() or x.islower()) else "_", groupname.strip()))


def get_groupname():
    iam_alias = iam.list_account_aliases()['AccountAliases'][0]

    return '%s_ssh' % format_groupname(groupname=iam_alias)


def start():
    print_logging('Deploying users')
    group = get_groupname()

    local_group = create_local_group(groupname=group)

    iam_user_list = populate_users(GroupName=group)
    sync_users(iam_users=iam_user_list, groupname=group, local_group_data=local_group)

    write_ssh_authorized_keys(iam_users=iam_user_list)
    write_sudo_config(groupname=group)
    print_logging('Done deploying users')


def stop():
    print_logging('Undeploying users')
    group = get_groupname()

    delete_sudo_config(groupname=group)
    delete_users(groupname=group)
    print_logging('Done undeploying users')

def print_usage():
    print('Usage: %s <start|stop>' % sys.argv[0])


def main():
    setup_logging()

    try:
        cmd = sys.argv[1]
    except IndexError:
        print_usage()
        sys.exit(1)

    if os.getuid() != 0:
        print_logging('Run this script as root!')
        sys.exit(1)

    if cmd == 'start':
        start()
    elif cmd == 'stop':
        stop()
    else:
        print_usage()
        sys.exit(1)

if __name__ == '__main__':
    main()