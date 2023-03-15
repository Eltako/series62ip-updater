#!/usr/bin/env python3

import base64
import datetime
import hashlib
import io
import json
import logging
import sys
import time
import typing

import OpenSSL.crypto
import cryptography
import cryptography.x509
import requests
import urllib3.exceptions
import cryptography.hazmat.primitives.asymmetric.rsa
from cryptography.hazmat.primitives import hashes
from tqdm import tqdm
from typeguard import typechecked

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@typechecked
class ConnectionConfig:
    def __init__(self, uri: str, ssl_verify: typing.Union[bool, str], timeout: int, pop: typing.Optional[str] = None, api_key: typing.Optional[str] = None):
        self.uri = uri
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.pop = pop
        self.api_key = api_key

        if not self.uri.startswith("http"):
            logging.debug("Device has no scheme set. Using https")
            self.uri = "https://{}".format(self.uri)


@typechecked
class EltakoDeviceCertificate:
    def __init__(self, cert):
        if isinstance(cert, OpenSSL.crypto.X509):
            self._cert = cert.to_cryptography()
        elif isinstance(cert, cryptography.x509.Certificate):
            self._cert = cert
        elif isinstance(cert, str):
            if not cert.startswith("-----BEGIN CERTIFICATE-----"):
                cert = "-----BEGIN CERTIFICATE-----\n" + cert
            if not cert.endswith("-----END CERTIFICATE-----"):
                cert = cert + "\n-----END CERTIFICATE-----"
            self._cert = cryptography.x509.load_pem_x509_certificate(cert.encode("ascii"))
        elif isinstance(cert, bytes):
            self._cert = cryptography.x509.load_der_x509_certificate(cert)
        else:
            raise Exception("Unsupported certificate type")

    @property
    def cert(self) -> cryptography.x509.Certificate:
        return self._cert

    def thumbprint(self) -> bytes:
        return self._cert.fingerprint(hashes.SHA256())

    def __str__(self) -> str:
        return f"""\
CN: {self.cert.subject}\n\
notBefore: {self.cert.not_valid_before}\n\
notAfter: {self.cert.not_valid_after}\n\
digest: {self.thumbprint().hex()}\
"""


@typechecked
class UpdateInfo:
    def __init__(self, data):
        """
        param data: (pythonized) json data as returned by the device
        """
        if isinstance(data, str):
            data = json.loads(data)
        self._raw = data
        self.location = data["location"]
        self.auth = data["data"]["auth"]
        self.update = data["data"]["update"]
        self.current_version = data["data"]["currentVersion"]
        if "thumbprint" in data["data"]:
            self.thumbprint = data["data"]["thumbprint"]
        else:
            self.thumbprint: str = base64.urlsafe_b64encode(self.cert().thumbprint()).decode("ascii").replace("=", "")


    def server_uri(self) -> typing.Optional[str]:
        """
            Update server hint
        """
        return self.location

    def to_json(self):
        return self._raw

    def cert(self) -> EltakoDeviceCertificate:
        return EltakoDeviceCertificate(
            OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.auth["certificate"]))

    def __str__(self):
        return f"""\
Location: {self.location}\n\
Authentication: {self.auth}\n\
Thumbprint: {self.thumbprint}\n\
Payload: {self.update}\n\
Current version: {self.current_version}\n\
Certificate information:\n\
{self.cert()}\
"""


@typechecked
class FirmwareImageInfo:
    def __init__(self, metadata, data: bytes):
        self.metadata = metadata
        self.data: bytes = data

    def __str__(self):
        m = hashlib.sha256()
        m.update(self.data)
        return "Metadata:\n{}\nImage hash: {}".format(
            json.dumps(self.metadata, sort_keys=True, indent=4),
            m.hexdigest())


class SignedCsr:
    def __init__(self, data):
        self.data = data

    def cert(self) -> EltakoDeviceCertificate:
        return EltakoDeviceCertificate(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.data["cert"]))

    def __str__(self) -> str:
        return str(self.cert())


class CSR:
    def __init__(self, data):
        self.data = data
        header: str
        payload: str
        signature: str
        header, payload, signature = [base64.urlsafe_b64decode(x + "==") for x in self.data["csr"].split(".")]
        self.header = json.loads(header)
        self.payload = json.loads(payload)
        self.cert_tb = base64.urlsafe_b64decode(self.header["x5t#S256"] + "==")
        self.csr = cryptography.x509.load_pem_x509_csr(self.payload["csr"].encode("ascii"))

    def __str__(self):
        pubkey: cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey = self.csr.public_key()
        return f"""\
Cert thumbprint: {self.cert_tb.hex()}\n\
Subject: {self.csr.subject}\n\
Public key size: {pubkey.key_size}\n\
Public key modulus: {pubkey.public_numbers().n}\
"""

    def __eq__(self, other):
        return self.payload["csr"].encode("ascii") == other.payload["csr"].encode("ascii")


class TimeoutException(Exception):
    pass


class AuthenticationException(Exception):
    pass


@typechecked
class DeviceApi:
    def __init__(self, cfg: ConnectionConfig):
        self.cfg: ConnectionConfig = cfg
        self.session: requests.Session = requests.Session()
        self.api_version = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def __del__(self):
        self.disconnect()

    def disconnect(self):
        self.session.close()

    @property
    def timeout(self):
        return self.cfg.timeout

    def _absolute_uri(self, suffix: str) -> str:
        return "{host}/api/v{api}/{suffix}".format(host=self.cfg.uri, api=self.api_version, suffix=suffix)

    def post_login(self):
        """
        Login and get api key
        """
        uri = self._absolute_uri("login")
        logging.info("Login and getting api key from {}".format(uri))
        r: requests.Response = self.session.post(uri, json={"user": "admin", "password": self.cfg.pop},
                                                 verify=self.cfg.ssl_verify, timeout=self.cfg.timeout)
        logging.debug("Response({}): {}".format(r.status_code, r.content))
        if r.status_code not in [200]:
            logging.error("Failed to login to device and retrieve api key {}: {}".format(r.status_code, r.content))
            raise AuthenticationException("Failed to authenticate with device: {}".format(r.content))
        self.cfg.api_key = r.json()["apiKey"]

    def get_update_info(self) -> UpdateInfo:
        """
        Get update information from device
        """
        uri = self._absolute_uri("update/firmware")
        logging.info("Getting update information from {}".format(uri))
        r: requests.Response = self.session.get(uri, headers={"Authorization": self.cfg.api_key},
                                                verify=self.cfg.ssl_verify, timeout=self.cfg.timeout)
        logging.debug("Response ({}): {}".format(r.status_code, r.content))

        if r.status_code not in [200]:
            raise Exception("Failed to get update info from device {}: {}".format(r.status_code, r.content))
        return UpdateInfo(r.json())

    def upload_metadata(self, metadata) -> None:
        """
        Upload metadata of a single firmware update to a device
        """
        uri = self._absolute_uri("update/prepare")
        logging.debug("Metadata: {}".format(metadata))
        r: requests.Response = self.session.post(uri, headers={"Authorization": self.cfg.api_key}, json=metadata,
                                                 verify=self.cfg.ssl_verify, timeout=self.cfg.timeout)
        if r.status_code not in [200, 201]:
            raise Exception("Failed to begin update on device ({}): {}".format(r.status_code, r.text))

    def upload_image(self, image: bytes) -> None:
        """
        Upload firmware image to a device.
        You have to upload the respective metadata first.
        """
        uri = self._absolute_uri("update/firmware")
        logging.info("Upload uri: {}".format(uri))
        headers = {
            'Content-Type': 'application/octet-stream',
            'Authorization': self.cfg.api_key
        }
        logging.debug("Pushing firmware image with headers {}".format(headers))
        with tqdm.wrapattr(io.BytesIO(image), "read", total=len(image)) as data_with_progress:
            r: requests.Response = self.session.post(uri, data=data_with_progress, verify=self.cfg.ssl_verify,
                                                     headers=headers, timeout=self.cfg.timeout)
            if r.status_code not in [200, 201]:
                raise Exception("Failed to push firmware image to device ({}): {}".format(r.status_code, r.text))
        logging.info("Updating firmware was successful ({}): {}".format(r.status_code, r.text))
        # Device reboots after the update without disconnecting
        self.disconnect()

    def update_firmware(self, image: FirmwareImageInfo) -> None:
        """
        Update the firmware of a device
        """
        logging.info("Uploading metadata")
        self.upload_metadata(image.metadata)
        logging.info("Uploading metadata")
        self.upload_image(image.data)

    def get_csr(self, timeout_seconds: int = 800) -> CSR:
        """
        Retrieve certificate signing request from device in order to renew it.
        It may take quite a while to generate a new csr (up to 600 seconds)
        :param timeout_seconds: Give up after this many seconds and throw TimeoutException
        """
        logging.info("Retrieving csr")
        uri = self._absolute_uri("services/eltako/cert")
        now = datetime.datetime.now()
        while datetime.datetime.now() - now < datetime.timedelta(seconds=timeout_seconds):
            r: requests.Response = self.session.get(uri, headers={"Authorization": self.cfg.api_key},
                                                    verify=self.cfg.ssl_verify, timeout=self.cfg.timeout)
            logging.debug("Response ({}): {}".format(r.status_code, r.content))
            if r.status_code == 202:
                logging.info("Certificate update info not available yet")
            elif r.status_code == 200:
                return CSR(data=r.json())
            else:
                raise Exception("Failed to retrieve csr ({}): {}".format(r.status_code, r.text))
            logging.debug("Retrying in 10 seconds")
            time.sleep(10)
        raise TimeoutException("Timeout while trying to get cert info")

    def upload_new_cert(self, signed_cert: SignedCsr) -> None:
        """
        Upload a new certificate to the device
        """
        logging.info("Uploading new certificate")
        uri = self._absolute_uri("services/eltako/cert")
        r: requests.Response = self.session.post(uri, json=signed_cert.data,
                                                 headers={"Authorization": self.cfg.api_key},
                                                 verify=self.cfg.ssl_verify, timeout=self.cfg.timeout)
        logging.debug("Response ({}): {}".format(r.status_code, r.content))

        if r.status_code not in [200, 201]:
            raise Exception("Failed to upload new cert ({}): {}".format(r.status_code, r.text))


class AuthenticationError(Exception):
    pass


@typechecked
class ServerApi:
    def __init__(self, cfg: ConnectionConfig):
        self.cfg: ConnectionConfig = cfg
        self.session: requests.Session = requests.Session()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def __del__(self):
        self.disconnect()

    def disconnect(self):
        self.session.close()

    @property
    def timeout(self):
        return self.cfg.timeout

    def authenticate(self, ui: UpdateInfo) -> None:
        """
        Authenticate device with the update server.
        """
        # Now access the update server
        logging.info("Authenticating with update server")
        r: requests.Response = self.session.post("{}/api/v1/auth".format(self.cfg.uri), data=ui.auth,
                                                 verify=self.cfg.ssl_verify, timeout=self.cfg.timeout)

        if not (r.status_code in [200, 201]) or r.text != "true":
            raise AuthenticationError(
                "Failed to authenticate with update server {}: {}".format(r.status_code, r.content))

    def check_updates(self, ui: UpdateInfo) -> typing.List[str]:
        """
        Check for updates.
        Expects device to be authenticated.
        """

        update_check_params = {
            "version": ui.current_version,
            "thumbprint": ui.thumbprint,
            "full_path": True
        }
        logging.debug("Requesting update list for {}".format(update_check_params))
        r: requests.Response = self.session.get("{}/api/v1/update-check".format(self.cfg.uri),
                                                params=update_check_params,
                                                verify=self.cfg.ssl_verify, timeout=self.cfg.timeout)

        if r.status_code not in [200, 201]:
            logging.error("Failed to get possible updates from update server ({}): {}".format(r.status_code, r.text))
            sys.exit(1)

        return r.json()

    def fetch_update(self, ui: UpdateInfo, desired_version: str) -> FirmwareImageInfo:
        """
        Retrieve firmware update from update server
        :param ui: Auth info from the device
        :param desired_version: The version to fetch
        """
        logging.debug("Getting update for desired_version {}".format(desired_version))
        payload = ui.update
        payload["desiredVersion"] = desired_version
        logging.debug("Payload: {}".format(payload))
        r: requests.Response = self.session.post("{}/api/v1/update".format(self.cfg.uri), data=payload,
                                                 verify=self.cfg.ssl_verify, timeout=self.cfg.timeout)
        if r.status_code not in [200, 201]:
            logging.error("Failed to get update from update server ({}): {}".format(r.status_code, r.text))
            sys.exit(1)
        data = r.json()
        download_url = "{}/api/v1/download/{}".format(self.cfg.uri, data["imageid"])
        logging.debug("Getting update image from {}".format(download_url))
        r: requests.Response = requests.get(download_url, verify=self.cfg.ssl_verify, allow_redirects=True,
                                            timeout=self.cfg.timeout)
        if r.status_code not in [200, 201]:
            raise Exception("Failed to get image from download server ({}): {}".format(r.status_code, r.content))
        return FirmwareImageInfo(metadata=data, data=r.content)

    def sign_csr(self, csr: CSR) -> SignedCsr:
        """
        Renew a device certificate.
        Expects the device to be authenticated
        :param csr: certificate signing request of the device
        """

        r: requests.Response = self.session.post("{}/api/v1/sign".format(self.cfg.uri), json=csr.data,
                                                 verify=self.cfg.ssl_verify, timeout=self.cfg.timeout)
        logging.debug("Response ({}): {}".format(r.status_code, r.content))
        if not (r.status_code in [200, 201]):
            raise Exception("Failed to sign csr ({}): {}".format(r.status_code, r.content))
        return SignedCsr(r.json())
