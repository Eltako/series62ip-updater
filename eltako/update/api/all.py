#!/usr/bin/env python3
import copy
import datetime
import hashlib
import io
import json
import logging
import sys
import time
import typing
from urllib.parse import urlparse

import cryptography
import cryptography.x509
import requests
import urllib3.exceptions
import cryptography.hazmat.primitives.asymmetric.rsa
from cryptography.hazmat.primitives import hashes
from tqdm import tqdm
from typeguard import typechecked
import eltako.restapi.series62.api as series62
import eltako.restapi.series62.models.update as s62models
from eltako.restapi.series62.endpoints.endpoint import RequestFailedException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@typechecked
class ConnectionConfig:
    def __init__(self, uri: str, ssl_verify: typing.Union[bool, str], timeout: int, pop: typing.Optional[str] = None,
                 api_key: typing.Optional[str] = None):
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
        if isinstance(cert, cryptography.x509.Certificate):
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
    def __init__(self, data: typing.Union[str, dict, s62models.FirmwareUpdateRequestInfo]):
        if isinstance(data, str):
            data = s62models.FirmwareUpdateRequestInfo.from_json(data)
        elif isinstance(data, dict):
            print("data", data)
            data = s62models.FirmwareUpdateRequestInfo.from_dict(data)
        self._raw = data


    @property
    def data(self) -> s62models.FirmwareUpdateRequestInfo:
        return self._raw

    @property
    def location(self) -> typing.Optional[str]:
        """
            Update server hint
        """
        return self._raw.location

    @property
    def current_version(self) -> str:
        return self._raw.data.currentVersion

    @property
    def auth(self) -> s62models.UpdateAuthObject:
        return self._raw.data.auth

    @property
    def update(self) -> s62models.UpdateVersionObject:
        return self._raw.data.update

    @property
    def thumbprint(self) -> str:
        return self._raw.data.thumbprint

    def cert(self) -> EltakoDeviceCertificate:
        return EltakoDeviceCertificate(self._raw.data.auth.parsed_certificate())

    def __str__(self):
        return f"""\
Location: {self.location}\n\
Authentication: {self._raw.data.auth}\n\
Thumbprint: {self.thumbprint}\n\
Payload: {self._raw.data.update}\n\
Current version: {self._raw.data.currentVersion}\n\
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


@typechecked
class SignedCsr:
    def __init__(self, data: typing.Union[str, dict, s62models.CertificateUpdate]):
        if isinstance(data, str):
            data = s62models.CertificateUpdate.from_json(data)
        elif isinstance(data, dict):
            data = s62models.CertificateUpdate.from_dict(data)
        self._data = data

    @property
    def data(self) -> s62models.CertificateUpdate:
        return self._data

    def cert(self) -> EltakoDeviceCertificate:
        return EltakoDeviceCertificate(self._data.to_cryptography())

    def __str__(self) -> str:
        return str(self.cert())


@typechecked
class CSR:
    def __init__(self, data: typing.Union[str, dict, s62models.CertificateSigningRequest]):
        if isinstance(data, str):
            data = s62models.CertificateSigningRequest.from_json(data)
        elif isinstance(data, dict):
            data = s62models.CertificateSigningRequest.from_dict(data)
        self._data = data

    @property
    def data(self) -> s62models.CertificateSigningRequest:
        return self._data

    def __str__(self):
        csr = self._data.to_cryptography()
        return f"""\
Cert thumbprint: {self._data.signature_certificate_thumbprint().hex()}\n\
Subject: {csr.subject}\n\
Public key size: {csr.public_key().key_size}\n\
Public key modulus: {csr.public_key().public_numbers().n}\
"""

    def __eq__(self, other):
        if not isinstance(other, CSR):
            return False
        return self._data == other._data


class TimeoutException(Exception):
    pass


class AuthenticationException(Exception):
    pass


@typechecked
class DeviceApi:
    def __init__(self, cfg: ConnectionConfig):
        self.cfg: ConnectionConfig = cfg
        parsed_uri = urlparse(cfg.uri)
        con = series62.ApiConnection(scheme=parsed_uri.scheme,
                                     host=parsed_uri.hostname,
                                     port=parsed_uri.port or 443 if parsed_uri.scheme == "https" else 80,
                                     pop=cfg.pop,
                                     ssl_verify=cfg.ssl_verify,
                                     timeout=cfg.timeout)
        self._api = series62.Api(con)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def __del__(self):
        self.disconnect()

    def disconnect(self):
        self._api.disconnect()

    @property
    def timeout(self):
        return self.cfg.timeout

    def post_login(self):
        """
        Login and get api key
        """
        try:
            self._api.login()
        except RequestFailedException:
            raise AuthenticationException("Failed to authenticate with device")

    def get_update_info(self) -> UpdateInfo:
        """
        Get update information from device
        """
        return UpdateInfo(self._api.update().update_info())

    def upload_metadata(self, metadata) -> None:
        """
        Upload metadata of a single firmware update to a device
        """
        try:
            print(f"Uploading {metadata}")
            self._api.update().prepare_update(s62models.FirmwareUpdateInfo.from_dict(metadata))
        except RequestFailedException as re:
            raise Exception("Failed to begin update on device ({}): {}".format(re.request_response.status_code,
                                                                               re.request_response.text))

    def upload_image(self, image: bytes) -> None:
        """
        Upload firmware image to a device.
        You have to upload the respective metadata first.
        """
        try:
            with tqdm.wrapattr(io.BytesIO(image), "read", total=len(image)) as data_with_progress:
                self._api.update().push_update(data_with_progress, len(image))
        except RequestFailedException as re:
            raise Exception("Failed to push firmware image to device ({}): {}".format(re.request_response.status_code,
                                                                                      re.request_response.text))
        logging.info("Updating firmware was successful")
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
        now = datetime.datetime.now()
        while datetime.datetime.now() - now < datetime.timedelta(seconds=timeout_seconds):
            try:
                result = self._api.services().certificate_renewal().get_csr()
                match type(result):
                    case s62models.CertificateSigningRequestGenerationStatus:
                        logging.info("Certificate update info not available yet")
                    case s62models.CertificateSigningRequest:
                        return CSR(result)
            except RequestFailedException as re:
                raise Exception(
                    "Failed to retrieve csr ({}): {}".format(re.request_response.status_code, re.request_response.text))
            logging.debug("Retrying in 10 seconds")
            time.sleep(10)
        raise TimeoutException("Timeout while trying to get cert info")

    def upload_new_cert(self, signed_cert: SignedCsr) -> None:
        """
        Upload a new certificate to the device
        """
        logging.info("Uploading new certificate")
        self._api.services().certificate_renewal().upload_cert(signed_cert.data)


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
        r: requests.Response = self.session.post("{}/api/v1/auth".format(self.cfg.uri), json=ui.auth.to_dict(),
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
        payload = copy.deepcopy(ui.update)
        payload.desiredVersion = desired_version
        logging.debug("Payload: {}".format(payload))
        r: requests.Response = self.session.post("{}/api/v1/update".format(self.cfg.uri), json=payload.to_dict(),
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

        r: requests.Response = self.session.post("{}/api/v1/sign".format(self.cfg.uri), json=csr.data.to_dict(),
                                                 verify=self.cfg.ssl_verify, timeout=self.cfg.timeout)
        logging.debug("Response ({}): {}".format(r.status_code, r.content))
        if not (r.status_code in [200, 201]):
            raise Exception("Failed to sign csr ({}): {}".format(r.status_code, r.content))
        return SignedCsr(r.json())
