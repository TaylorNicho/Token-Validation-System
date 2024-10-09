import json
import base64
import hmac
import hashlib
from datetime import datetime, timedelta
import zlib
import base64
import cryptography


def base64url_decode(data):
    data += '=' * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(data.encode())


SECRET_KEY = b'supersecretkey'
def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')

def generate_token(username, permissions, system_name):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "usr": username,
        "perm": permissions,
        "sys": system_name,
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(days=1)).timestamp())  
    }
    
    header_json = json.dumps(header, separators=(',', ':')).encode()
    payload_json = json.dumps(payload, separators=(',', ':')).encode()
    
    # Compress 
    payload_compressed = zlib.compress(payload_json)
    
    # encode
    header_encoded = base64url_encode(header_json)
    payload_encoded = base64url_encode(payload_compressed)
    
    # create signature
    signature = hmac.new(SECRET_KEY, header_encoded + b'.' + payload_encoded, hashlib.sha256).digest()
    signature_encoded = base64url_encode(signature)
    
    # Create token
    token = header_encoded + b'.' + payload_encoded + b'.' + signature_encoded
    return token.decode()


def validate_token(token):
    try:
        header_encoded, payload_encoded, signature_encoded = token.split('.')
        
        # Decode
        header = base64url_decode(header_encoded)
        payload_compressed = base64url_decode(payload_encoded)
        
        # Decompress
        try:
            payload_json = zlib.decompress(payload_compressed)
        except zlib.error as e:
            print(f'Error decompressing payload: {e}')
            return False, None
        
        # Verify 
        expected_signature = hmac.new(SECRET_KEY, header_encoded.encode() + b'.' + payload_encoded.encode(), hashlib.sha256).digest()
        expected_signature_encoded = base64url_encode(expected_signature).decode()
        
        if not hmac.compare_digest(signature_encoded, expected_signature_encoded):
            return False, None
        
        # Check token expiry
        payload_data = json.loads(payload_json)
        expiration_time = payload_data.get('exp')
        if expiration_time is None:
            print('Token does not contain expiration time')
            return False, None
        
        current_time = datetime.utcnow().timestamp()
        if current_time > expiration_time:
            print('Token has expired')
            return False, None
        
        return True, payload_data
    
    except Exception as e:
        print(f'Token validation error: {e}')
        return False, None

