import dateutil.parser
from datetime import datetime, timedelta
from signxml import XMLSignatureProcessor

class SP():
    ''' Abstract class that describes a Service Provider.'''
    
    def __init__(self):
        pass
    
    service_provider = None

    TEMPLATES = {
        'response'  : None,
        'assertion' : None,
        'attribute' : None
    }
   
    C14_ALG = str(list(XMLSignatureProcessor.known_c14n_algorithms)[2])
   
    def connect(self):
        '''Connect to the Service Provider'''
        raise NotImplementedError("Class %s doesn't implement connect()" % self.__class__.__name__)
  
    def create_assertion(self):
        '''Create the SAML assertion for the SP''' 
        raise NotImplementedError("Class %s doesn't implement create_assertion()" % self.__class__.__name__)
   
    def sign_assertion(self):
        '''Sign the assertion with the private key'''
        raise NotImplementedError("Class %s doesn't implement sign_assertion()" % self.__class__.__name__)
    
    def gen_id(self):
        '''Generate an assertion id'''
        raise NotImplementedError("Class %s doesn't implement gen_id()" % self.__class__.__name__)
  
    @classmethod
    def gen_timestamp(cls, days=0, hours=0, minutes=0, seconds=0, base_time=None):
        ''' Generates a zulu timestamp (i.e. UTC+0). Accepts time difference from current time.
            :param days: number of day difference
            :param hours: number of hour difference
            :param minutes: number of minute difference
            :param seconds: number of second difference
            :param base_time: base timestamp calculate the diffs. default it current time.
            :return: string zulu timestamp
        '''

        if base_time:
            # Parse the base_time to a datetime object
            base_time = dateutil.parser.parse(base_time)
        else:
            # Get current time as the base time
            base_time = datetime.utcnow()
        # Apply time delta
        if days or minutes or seconds:
            timestamp = base_time + timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)
        else:
            timestamp = base_time
        return timestamp.isoformat()[:-3] + "Z"