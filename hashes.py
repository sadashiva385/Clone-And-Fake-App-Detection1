import hashlib
import logging
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import load_der_x509_certificate
from androguard.misc import AnalyzeAPK

logger = logging.getLogger(__name__)

def generate_apk_hash(apk_path: str) -> str:
    sha256 = hashlib.sha256()
    try:
        with open(apk_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"Hash generation failed: {e}")
        raise

def extract_metadata(apk_path: str) -> dict:
    try:
        a, _, _ = AnalyzeAPK(apk_path)
        certs = []
        for cert in a.get_certificates():
            try:
                der_data = cert.get_raw() 
                x509_cert = load_der_x509_certificate(der_data)
                public_key = x509_cert.public_key().public_bytes(
                    encoding=Encoding.PEM,
                    format=PublicFormat.SubjectPublicKeyInfo
                ).decode()
                algorithm = x509_cert.signature_algorithm_oid.dotted_string
            except Exception:
                public_key = "Unknown"
                algorithm = "Unknown"
                
            certs.append({
                'public_key': public_key,
                'signature_algorithm': algorithm
            })
        return {
            'package_name': a.get_package(),
            'version': a.get_androidversion_name(),
            'permissions': a.get_permissions(),
            'certificates': certs,
            'activities': a.get_activities()
        }
    except Exception as e:
        logger.error(f"Metadata extraction failed: {e}")
        return {}

# import hashlib
# import logging
# from key import hashes_csv
# from androguard.misc import AnalyzeAPK

# logger = logging.getLogger(__name__)

# def generate_apk_hash(apk_path: str) -> str:
#     #generate SHA256 hash of APK
#     sha256 = hashlib.sha256()
#     try:
#         with open(apk_path, 'rb') as f:
#             while chunk := f.read(8192):
#                 sha256.update(chunk)
#         return sha256.hexdigest()
#     except Exception as e:
#         logger.error(f"Hash generation failed: {e}")
#         raise

# def extract_metadata(apk_path: str) -> dict:
#     # extract package name and version from apk
#     try:
#         a, _, _ = AnalyzeAPK(apk_path)
#         return {
#             'package_name': a.get_package(),
#             'version': a.get_androidversion_name(),
#             'permissions': a.get_permissions(),
#             'certificates': [
#                 {
#                     'public_key': cert.get_public_key(),
#                     'signature_algorithm': cert.get_signature_name()
#                 }
#                 for cert in a.get_certificates()
#                 ],
#             # 'certificates': [cert.get_data() for cert in a.get_certificates()] if a.get_certificates() else [],
#             'activities': a.get_activities()
#         }
#     except Exception as e:
#         logger.error(f"Metadata extraction failed: {e}")
#         return{}