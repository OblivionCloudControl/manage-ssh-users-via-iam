# Manage SSH users via IAM

When this script is called with the parameter to deploy new users it will:

1. Retrieve a list of IAM users which are member of a group. This group should be named as '&lt;aws_alias&gt;_ssh'
1. Download the available SSH keys from IAM (available in the console under CodeCommit deploy keys)
1. Create a local group on the instance
1. Create local users on the instance
1. Write downloaded SSH keys to ~/.ssh/authorized_keys for each user
1. Configure sudo to allow root-access for the users

This script can be run periodically. It will execute the steps above, but also would locallly delete users which are deleted in IAM.

When this script is called with the parameter to undeploy new users it will:

1. Delete all users which are member of the group
1. Delete the group

There is a filter to prevent deletion of certain system users.

## Requirements

### Python packages
```
$ sudo pip install -r requirements.txt
```
### EC2 resource
This script is written to be used on an EC2 instance. This instance must launched with an instance role and a proper policy attached to make API calls to IAM.

## Deploying users
```
$ sudo ./src/sync_users.py start
```

## Undeploying users
```
$ sudo ./src/sync_users.py stop
```

## TODO

* Create deployable packages
* Provide initscripts, cronjobs, etc.
* Allow cross-account IAM access
