# alohomora

alohomora is a CLI utility, written in Python, that helps SAML-federated users
get API keys for their AWS accounts.  It works with single-factor IdPs in
general, and also supports multi-factor via [Duo Security](https://duo.com).
We'd love to support other MFA options, but that's all we have access to right
now.  Send us a PR with yours!


## Installation

Like all Python apps, we recommend you install this into a virtual environment,
but the choice is yours.

    pip install alohomora

### Optional U2F support installation

Alohomora has optional U2F support, which can be installed alongside alohomora using pip:

    pip install alohomora[u2f]

Please note that this requires a few OS level packages to be installed.
For Centos 7, it requires the following:

    yum groupinstall 'Development Tools'
    yum install python[2,3]-devel
    yum install libusbx-devel
    yum install systemd-devel

For Debian based systems, you'll need the following:

    apt install build-essential
    apt install python[2,3]-dev
    apt install libusb-1.0-0-dev
    apt install libudev-dev

## Basic Configuration

You can create a ~/.alohomora file to configure the tool.  It will store
infomation like the URL of your SAML Identity Provider that shouldn't change
very often.  Alternately, you can specify most config options on the command
line as well.

The file looks like a standard Python config file:

```ini
[default]
idp-url = https://sso.mycompany.com/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices
username = myuser
```

A CLI-based version of this would be

```
$ alohomora --username myuser --idp-url https://sso.mycompany.com/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices
```


## Usage

You can call `alohomora` directly from the command line.

```
$ alohomora
Password:
Please select an authentication method
[ 0 ] Duo Push
[ 1 ] Phone Call
[ 2 ] Passcode
ID: 0
Pushed a login request to your device...

Please choose the role you would like to assume:
[ 0 ] arn:aws:iam::123456789012:role/a-fine-role
[ 1 ] arn:aws:iam::345678901234:role/a-particularly-fine-role
Selection:  1


----------------------------------------------------------------
Your new access key pair has been stored in the AWS configuration file /Users/myuser/.aws/credentials under the saml profile.
To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).
----------------------------------------------------------------
```

If you have multiple devices associated with your account, you will be asked to
select the device you want to use.


## Advanced Configuration


### MFA Configuration for Duo

If you have multiple Duo devices, you can add `auth-device` to your
configuration to select which device to use. If you aren't sure what
the names of your devices are, run `alohomora` once without an auth device
selected to have it display a prompt with a list of device names.
The auth device parameters is case-insensitive.

In order to select a default Duo MFA method, you can add `auth-method` to your 
configuration.  A nonexhaustive list of supported values for Duo are:

- push
- call
- passcode

```
$ alohomora --auth-method call
```

```ini
[default]
idp-url = https://sso.mycompany.com/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices
auth-method = push
```


### Alohomora Config Profiles

You can create multiple configuration profiles in the ~/.alohomora file, for example:

```ini
[default]
idp-url = https://sso.mycompany.com/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices
auth-method = push
role-name = a-fine-role

[particularly-fine]
idp-url = https://sso.mycompany.com/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices
auth-method = push
role-name = a-particularly-fine-role
```

If you specify nothing else, alohomora will use the `default` profile.  To use 
the `particularly-fine` configuration, simply run 

```
$ alohomora --alohomora-profile particularly-fine
```


### AWS Config Profiles

By default, alohomora saves the credentials under the `saml` profile.  If you 
wish to save the generated IAM keys under a different AWS profile name, you can 
specify the `aws-profile` option.  Via the CLI this looks like

```
alohomora --aws-profile myprofile
```

Or in a config file:

```ini
[default]
...
aws-profile = myprofile
```


### Account Names

If you have many AWS accounts, keeping track of account IDs can be hard.  We've 
added the ability to drop a map of account IDs to friendly names in the config
file, that should help solve this problem.  To make use of this, add a new
`[account_map]` section to the config like so:

```ini
[default]
...

[account_map]
123456789012 = Dev Account
210987654321 = Prod Account
```

This will modify the roles that get printed out, like so:

```
Please choose the role you would like to assume:
[ 0 ] Dev Account: sso-admins - arn:aws:iam::123456789012:role/sso-admins
[ 1 ] Prod Account: sso-finance-readers - arn:aws:iam::210987654321:role/sso-finance-readers
```

Alohomora doesn't support feeding these in via the command line, because that
would make your command WAY too long.


### Automatic Role Selection

If you have many AWS accounts/roles and wish to have alohomora always use a 
specific account and role, this can be done by specifying them in the 
configuration section like so:

```ini
[default]
idp-url = https://sso.mycompany.com/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices
auth-method = push
account = 112233445566
role-name = sso-admins
```


### AWS Partition Selection

If you run separate IdPs for your different commercial and GovCloud accounts, 
alohomora should "just work": that is, the role lists will all update correctly,
the assertions will be formatted properly, etc.  We autodiscover the partition
you're working in based off the roles that are handed back to us.

However, if you're using the same IdP to provide access to both commercial and
GovCloud, **and** you're asking Alohomora to do automatic role selection, it's
hard for us to tell which partition you want to use.  You may need to manually
specify that by adding an `aws-partition` option as below.

```ini
[default]
...
aws-partition = aws

[awsgov]
...
aws-partition = aws-us-gov
```

Or, via the CLI:

```
$ alohomora --aws-partition aws-us-gov
```


## Debugging

Logs are written to `~/.alohomora.log` by default.


## Future Features

  * Respect the default factor option on the Duo account (push vs. text vs. call)

## Note for Windows Users

This does **NOT** work in Cygwin or Cygwin based shells in Windows (such as Gitbash).  Use cmd instead.


## Contributors (Alphabetical)

* @abrooks
* @bcaselden-viasat
* @gcochard
* @gdw2
* @marksidell
* @Serilleous
* @skemper
* @wkronmiller
* @xrl


## Thanks

This application was written with heavy assistance from an 
[AWS Security Blog post](http://blogs.aws.amazon.com/security/post/TxU0AVUS9J00FP/How-to-Implement-a-General-Solution-for-Federated-API-CLI-Access-Using-SAML-2-0) 
that Quint Van Deman of AWS wrote up.  Thanks Quint!
