#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Any code, applications, scripts, templates, proofs of concept, documentation
# and other items provided by OBLCC under this SOW are 'OBLCC Content,'' as defined
# in the Agreement, and are provided for illustration purposes only. All such
# OBLCC Content is provided solely at the option of OBLCC, and is subject to the
# terms of the Addendum and the Agreement. Customer is solely responsible for
# using, deploying, testing, and supporting any code and applications provided
# by OBLCC under this SOW.
#
# (c) 2016 Oblivion Cloud Control
# Author: S. Huizinga <steyn@oblcc.com>

import grp
import os
import pwd

import boto3
import argparse
import urllib2
import logging
import sys
from logging.handlers import SysLogHandler

# Get command line arguments
parser = argparse.ArgumentParser(prog='sync_users')
parser.add_argument('-a', '--accountid', help='AWS account id', required=False)
parser.add_argument('-r', '--role', help='AWS role name to assume', required=False)
parser.add_argument('action', choices=('start', 'stop'))
parser_required_named = parser.add_argument_group('required named arguments')
parser_required_named.add_argument('-g', '--group', help='IAM group that contains SSH users', required=True)
args = parser.parse_args()

# Ensure that both accountid and role are defined when using AssumeRole
if args.accountid and not args.role or args.role and not args.accountid:
    parser.error('AssumeRole needs both accountid and role specified')

if args.accountid is None:
    try:
        iam = boto3.client('iam')
    except Exception as e:
        print(e)
        sys.exit(1)
else:
    # If we can retrieve the instance id we can use it in the assume role session name
    try:
        instance_id = urllib2.urlopen('http://169.254.169.254/latest/meta-data/instance-id', timeout=3).read()
    except urllib2.URLError:
        instance_id = 'unknown'

    try:
        # Use STS to AssumeRole to the given account id and role
        sts_client = boto3.client('sts')

        assumed_role_object = sts_client.assume_role(
            RoleArn="arn:aws:iam::" + args.accountid + ":role/" + args.role,
            RoleSessionName=parser.prog + "-" + instance_id
        )

        access_key = assumed_role_object['Credentials']['AccessKeyId']
        secret_key = assumed_role_object['Credentials']['SecretAccessKey']
        session_token = assumed_role_object['Credentials']['SessionToken']

        iam = boto3.client('iam', aws_access_key_id=access_key,
                           aws_secret_access_key=secret_key,
                           aws_session_token=session_token, )
    except Exception as e:
        print(e)
        sys.exit(1)


log = logging.getLogger(__name__)


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


def list_keys_per_user(**kwargs):
    return [
        iam.get_ssh_public_key(UserName=ssh_public_key['UserName'], SSHPublicKeyId=ssh_public_key['SSHPublicKeyId'],
                               Encoding='SSH')['SSHPublicKey']
        for ssh_public_key in iam.list_ssh_public_keys(**kwargs)['SSHPublicKeys']]


def populate_users(**kwargs):
    return [
        dict({unicode('authorized_keys'): unicode('\n'.join([
                                                                '%s SSHPublicKeyId=%s' % (
                                                                    ssh_key['SSHPublicKeyBody'],
                                                                    ssh_key['SSHPublicKeyId'])
                                                                for ssh_key in
                                                                list_keys_per_user(UserName=iam_user['UserName'])
                                                                if ssh_key['Status'] == 'Active'
                                                                ])),
              unicode('ssh_user'): unicode(iam_user['UserName'].lower())}.items() + iam_user.items())
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
        log.info('Create group %s' % groupname)

        create_group_command = 'groupadd %s' % groupname
        os.system(create_group_command)

        return grp.getgrnam(groupname)


def create_user(username, groupname, rotate_user=False):
    if user_exists(username=username) and rotate_user:
        log.info('User %s already exists, but not part of group. Rotating user' % username)
        delete_user(username)

    log.info('Create user %s' % username)
    create_user_command = 'useradd -G %s,wheel -c "%s" -m %s' % (groupname, username, username)
    os.system(create_user_command)

    return user_exists(username=username)


def sync_users(iam_users, groupname, local_group_data):
    iam_usernames = [iam_user['ssh_user'] for iam_user in iam_users]
    log.info('Got IAM users: %s' % ', '.join(sorted(iam_usernames)))

    gr_name, gr_passwd, gr_gid, gr_mem = local_group_data
    log.info('Got local users: %s' % ', '.join(sorted(gr_mem)))

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

        log.info('Writing authorized_keys for user %s' % iam_user['ssh_user'])
        f = open(ssh_authorized_keys, 'w')
        f.write('%s\n' % iam_user['authorized_keys'])
        f.close()

        os.chown(ssh_authorized_keys, pw_uid, pw_gid)
        os.chmod(ssh_authorized_keys, 0600)


def write_sudo_config(groupname):
    sudoers_file = os.path.join('/etc/sudoers.d/', groupname)

    log.info('Writing sudoers config')
    f = open(sudoers_file, 'w')
    f.write('%%%s ALL=(ALL) NOPASSWD:ALL' % groupname)
    f.close()

    os.chown(sudoers_file, 0, 0)
    os.chmod(sudoers_file, 600)


def delete_sudo_config(groupname):
    sudoers_file = os.path.join('/etc/sudoers.d/', groupname)

    return True if not os.path.exists(sudoers_file) else os.remove(sudoers_file)


def delete_user(username):
    log.info('Delete user %s' % username)

    if username in ('root', 'ec2-user', 'centos', 'ubuntu'):
        log.info('Cannot delete user')
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


def start(group):
    log.info('Deploying users')

    local_group = create_local_group(groupname=group)

    try:
        iam_user_list = populate_users(GroupName=group)
    except Exception as e:
        print(e)

    sync_users(iam_users=iam_user_list, groupname=group, local_group_data=local_group)

    write_ssh_authorized_keys(iam_users=iam_user_list)
    write_sudo_config(groupname=group)
    log.info('Done deploying users')


def stop(group):
    log.info('Undeploying users')

    delete_sudo_config(groupname=group)
    delete_users(groupname=group)
    log.info('Done undeploying users')


def main():

    group = args.group

    setup_logging()

    if os.getuid() != 0:
        log.info('Run this script as root!')
        sys.exit(1)

    if args.action == 'start':
        start(group)
    elif args.action == 'stop':
        stop(group)
    else:
        log.info('Unknown action')
        sys.exit(1)


if __name__ == '__main__':
    main()
