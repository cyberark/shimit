import os, botocore, boto3, subprocess
import lxml.etree as etree
from base64 import b64encode, b64decode
from botocore import client
from signxml import XMLSigner, XMLSignatureProcessor
from uuid import uuid4
from service_provider import SP


# Globals
AWS_USER_AGENT = "AWS Signin, aws-internal/3"
DEFAULT_C14_ALG = str(list(XMLSignatureProcessor.known_c14n_algorithms)[2]) 


class AWS(SP):
    ''' AWS Service Provider Class'''

    def __init__(self, user_agent=AWS_USER_AGENT, c14_alg=DEFAULT_C14_ALG):
        self.USER_AGENT = user_agent
        SP.C14_ALG = c14_alg

    # Service Provider Specific constants
    SP.service_provider = ''
    AWS_ROLE = 'https://aws.amazon.com/SAML/Attributes/Role'
    USER_AGENT = AWS_USER_AGENT

    # Response templates
    SP.TEMPLATES['response']        = '<samlp:Response ID="{id}" Version="2.0" IssueInstant="{issue_instant}" Destination="https://signin.aws.amazon.com/saml" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">{issuer}</Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>{assertion}</samlp:Response>'
    SP.TEMPLATES['assertion']       = '<Assertion ID="{id}" IssueInstant="{issue_instant}" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Issuer>{issuer}</Issuer><Subject><NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{user}</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData NotOnOrAfter="{confirm_not_on_after}" Recipient="{recipient}" /></SubjectConfirmation></Subject><Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_after}"><AudienceRestriction><Audience>urn:amazon:webservices</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName"><AttributeValue>{role_session_name}</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant="{authn_instant}" SessionIndex="{session_index}"><AuthnContext><AuthnContextClassRef>urn:federation:authentication:windows</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion>'
    SP.TEMPLATES['attribute']       = '<Attribute Name="https://aws.amazon.com/SAML/Attributes/Role"><AttributeValue>arn:aws:iam::{arn}:saml-provider/ADFS,arn:aws:iam::{arn}:role/{role}</AttributeValue></Attribute>'
    SP.TEMPLATES['principal_arn']   = "arn:aws:iam::{arn}:saml-provider/ADFS"
    SP.TEMPLATES['role_arn']        = "arn:aws:iam::{arn}:role/{role}"


    @classmethod
    def gen_id(cls):
        '''
        Create a GUID for the assertion
        :return: GUID string
        '''
        return "_" + str(uuid4())


    @classmethod
    def create_assertion(cls, time, issuer, user, confirm_not_on_after, recipient, not_on_after, role_session_name, roles, arn):
        ''' Creates a etree.root of a SAML2.0 assertion based on parameters provided.
            All parameters should be strings
            :param time: time of creation
            :param issuer: the IdP issued the assertion
            :param user: identity of the user
            :param confirm_not_on_after: assertion expiration date
            :param recipient: receiving SP
            :param not_on_after: session expiration date
            :param role_session_name: session name
            :param roles: aws roles
            :param arn: amazon account id
            :return: etree.root object containing the assertion generated
        '''
        # Create etree root element
        assertion = cls.TEMPLATES['assertion'].format(
            id=cls.gen_id(),
            issue_instant=time,
            issuer=issuer,
            user=user,
            confirm_not_on_after=confirm_not_on_after,
            recipient=recipient,
            not_before=time,
            not_on_after=not_on_after,
            role_session_name=role_session_name,
            authn_instant=cls.gen_timestamp(minutes=3),
            session_index=cls.gen_id()
        )
        parser = etree.XMLParser(remove_comments=False)
        root = etree.fromstring(assertion, parser=parser)

        # Populate AttributeStatement
        for role in roles:
            attr = cls.TEMPLATES['attribute'].format(arn=arn, role=role)
            attr_statement = root.find('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement')
            attr_statement.append(etree.fromstring(attr))
        return root


    @classmethod
    def sign_assertion(cls, root, key, cert):
        ''' Reads the certificate and private key to memory from the paths provided.
            uses signxml module to sign the root object provided.
            :param root: root object to sign
            :param : private RSA key to sign with
            :param : public certificate of the private key
            :return: a signed root object
        '''
        # Read the private key and certificate
        key = open(key, "r").read()
        cert = open(cert, "r").read()

        # Set up xml signer object
        signer = XMLSigner(c14n_algorithm=cls.C14_ALG)

        # Sign the Assertion
        return signer.sign(root, key=key, cert=cert)
    

    @classmethod
    def load(cls, saml_response):
        ''' Returns the ARN and role name from an encoded SAML response.
            :param saml_response: encoded saml response
            :return: amazon account ID of the response and the role name
        '''
        # Load the saml response as a etree object
        root = etree.fromstring(b64decode(saml_response))

        # Find the assertion
        assertion = root.find('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')

        # FInd the attribute statement
        attr_statement = assertion.find('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement')

        # Iterate attributes to find the first role which will be assumed
        for attr in attr_statement:
            if attr.attrib["Name"] == cls.AWS_ROLE:
                role = attr[0].text
                break

        # Get the ARN and role name from the value
        arn = role.split(':')[4]
        role_name = role.split('/')[-1]

        return arn, role_name
    

    @classmethod
    def assume_role(cls, role_arn, principal_arn, saml_response, duration=3600):
        ''' Assumes the desired role using the saml_response given. The response should be b64 encoded.
            Duration is in seconds
            :param role_arn: role amazon resource name
            :param principal_arn: principal name
            :param saml_response: SAML object to assume role with
            :param duration: session duration (default: 3600)
            :return: AWS session token
        '''
        # Assume role with new SAML
        conn = boto3.client('sts', config=client.Config(signature_version=botocore.UNSIGNED, user_agent=cls.USER_AGENT, region_name=None))
        aws_session_token = conn.assume_role_with_saml(
            RoleArn=role_arn,
            PrincipalArn=principal_arn,
            SAMLAssertion=saml_response,
            DurationSeconds=duration,
            
        )
        return aws_session_token


    @classmethod
    def apply_cli_session(cls, creds, region):
        ''' Applies the given credentials (i.e. AccessKey, SecretAccessKey and SessionToken) to a new shell to use with aws cli.
            The credentials are used as environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_DEFAULT_REGION
            that aws cli uses.
            The region is the desired region to connect to (e.g. us-east-1).
            :param : boto3 returned credentials dict
            :param region: aws region to connect to
        '''
        # Set up environment for opening shell with credentials
        os.environ["AWS_ACCESS_KEY_ID"] = creds["AccessKeyId"]
        os.environ["AWS_SECRET_ACCESS_KEY"] = creds["SecretAccessKey"]
        os.environ["AWS_SESSION_TOKEN"] = creds["SessionToken"]
        os.environ["AWS_DEFAULT_REGION"] = region

        # Open up a new shell
        if os.name == 'nt':
            subprocess.Popen(r"cmd", creationflags=subprocess.CREATE_NEW_CONSOLE)
        else:
            os.system(os.environ['SHELL'])