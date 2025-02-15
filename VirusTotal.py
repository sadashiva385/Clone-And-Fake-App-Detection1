import requests
import logging
from key import VIRUSTOTAL_API_KEY

logger = logging.getLogger(__name__)

class VirusTotalClient:
    def __init__(self):
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
    def check_hash(self, file_hash: str) -> dict:
        # check file hash against VirusTotal database
        try:
            response = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            return{}