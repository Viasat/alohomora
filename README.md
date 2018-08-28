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


## Configuration

You can create a ~/.alohomora file to configure the tool.  It will store
infomation like the URL of your SAML Identity Provider that shouldn't change
very often.  Alternately, you can specify any config option on the command line
as well.

The file looks like a standard Python config file:

```
[default]
idp-url = https://sso.mycompany.com/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices
username = myuser
```

A CLI-based version of this would be

```
alohomora --username myuser --idp-url https://sso.mycompany.com/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices
```

In order to select a default device, you can add `auth-method` to the `default` 
section of `~/.alohomora`. A nonexhaustive list of supported values are:
- push
- call
- passcode

```
[default]
idp-url = https://sso.mycompany.com/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices
auth-method = push
```

## Account Names

If you have many AWS accounts, keeping track of account IDs can be hard.  We've 
added the ability to drop a map of account IDs to friendly names in the config
file, that should help solve this problem.  To make use of this, add a new
`[account_map]` section to the config like so:

```
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
[ 1 ] Prod Account: sso-finance-readers - arn:aws:iam::210987654321:role/sso-admins
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


## Debugging

Logs are written to `~/.alohomora.log` by default.


## Future Features

  * Respect the default factor option on the Duo account (push vs. text vs. call)
  * Provide some way of mapping account numbers to account names


## Thanks

This application was written with heavy assistance from an 
[AWS Security Blog post](http://blogs.aws.amazon.com/security/post/TxU0AVUS9J00FP/How-to-Implement-a-General-Solution-for-Federated-API-CLI-Access-Using-SAML-2-0) 
that Quint Van Deman of AWS wrote up.  Thanks Quint!
