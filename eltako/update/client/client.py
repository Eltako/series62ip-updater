#!/usr/bin/env python3
from eltako.update.api import *
import typing
import json
from typeguard import typechecked


class CfgException(Exception):
    pass


@typechecked
class Ok:
    def __init__(self, msg: typing.Optional[str]):
        self.msg = msg

    def __str__(self):
        if self.msg:
            return "Ok({})".format(self.msg)
        else:
            return "Ok"


@typechecked
class Client:

    def __init__(self, args):
        self.args = args
        self._device_api: typing.Optional[DeviceApi] = None
        self._server_api: typing.Optional[ServerApi] = None

    def need_device_api_to(self, msg: str) -> DeviceApi:
        if self.args.device_uri is None:
            raise CfgException("Need device uri to {}".format(msg))

        if self._device_api is None:
            self._device_api = DeviceApi(
                ConnectionConfig(self.args.device_uri, ssl_verify=self.args.ssl_verify, timeout=self.args.timeout,
                                 pop=self.args.pop, api_key=self.args.api_key))

            if self.args.api_key is None:
                if self.args.pop:
                    self._device_api.post_login()
                else:
                    raise CfgException("Need either API key or Proof-of-Possession to login to device")

        return self._device_api

    def need_server_api_to(self, msg: str) -> ServerApi:
        if self.args.server_uri is None:
            raise CfgException("Need server uri to {}".format(msg))
        self._server_api = ServerApi(
            ConnectionConfig(self.args.server_uri, ssl_verify=self.args.ssl_verify, timeout=self.args.timeout))
        return self._server_api

    def get_update_info(self, force_remote: bool = False) -> UpdateInfo:
        if not hasattr(self.args, "auth") or self.args.auth is None or force_remote:
            device_api = self.need_device_api_to("retrieve authentication info from device")
            ui = device_api.get_update_info()
            if hasattr(self.args, "auth") and self.args.auth is not None:
                with open(self.args.auth, "wt") as f:
                    f.write(json.dumps(ui.to_json(), sort_keys=True, indent=4))
            return ui
        else:
            with open(self.args.auth, "rt") as f:
                return UpdateInfo(json.load(f))

    def get_available_versions(self, force_remote: bool = False) -> typing.List[str]:
        ui: UpdateInfo = self.get_update_info()
        server_api = self.need_server_api_to("fetch available versions from update server")
        server_api.authenticate(ui)
        return server_api.check_updates(ui)

    def get_firmware_update(self, force_remote: bool = False) -> FirmwareImageInfo:
        if not hasattr(self.args, "firmware") or self.args.firmware is None or force_remote:
            if not hasattr(self.args, "version") or self.args.version is None:
                versions = self.get_available_versions()
                if len(versions) == 0:
                    print("No versions available")
                    raise Exception("No firmware updates available")
                setattr(self.args, "version", versions[0])
                logging.info("Selected version {}".format(self.args.version))

            ui: UpdateInfo = self.get_update_info()
            server_api = self.need_server_api_to("fetch firmware update from update server")
            server_api.authenticate(ui)
            fw = server_api.fetch_update(ui, self.args.version)
            if hasattr(self.args, "firmware") and self.args.firmware is not None:
                with open(self.args.firmware, "wt") as f:
                    f.write(json.dumps({"metadata": fw.metadata, "data": base64.b64encode(fw.data).decode()}))
            return fw
        else:
            with open(self.args.firmware, "rt") as f:
                d = json.load(f)
                return FirmwareImageInfo(metadata=d["metadata"], data=base64.b64decode(d["data"]))

    def update_device(self, force_remote: bool = False) -> Ok:
        fw = self.get_firmware_update()
        device_api = self.need_device_api_to("upload firmware update to device")
        if not self.args.no_metadata:
            logging.info("Uploading metadata")
            device_api.upload_metadata(fw.metadata)
        if not self.args.no_image:
            logging.info("Uploading image")
            device_api.upload_image(fw.data)
        return Ok(None)

    def get_csr(self, force_remote: bool = False) -> CSR:
        if not hasattr(self.args, "csr") or self.args.csr is None or force_remote:
            device_api = self.need_device_api_to("fetch certificate signing request from device")
            csr = device_api.get_csr()
            if hasattr(self.args, "csr") and self.args.csr is not None:
                with open(self.args.csr, "wt") as f:
                    f.write(json.dumps(csr.data))
            return csr
        else:
            with open(self.args.csr, "rt") as f:
                return CSR(data=json.load(f))

    def get_cert(self, force_remote: bool = False) -> SignedCsr:
        if not hasattr(self.args, "cert") or self.args.cert is None or force_remote:
            ui = self.get_update_info()
            csr = self.get_csr()
            server_api = self.need_server_api_to("to fetch certificate from update server")
            server_api.authenticate(ui)
            signed_cert = server_api.sign_csr(csr)
            if hasattr(self.args, "cert") and self.args.cert is not None:
                with open(self.args.cert, "wt") as f:
                    f.write(json.dumps({"data": signed_cert.data}))
            return signed_cert
        else:
            with open(self.args.cert, "rt") as f:
                return SignedCsr(data=json.load(f)["data"])

    def renew_cert(self, force_remote: bool = False) -> Ok:
        cert = self.get_cert()
        device_api = self.need_device_api_to("upload new certificate to the device")
        device_api.upload_new_cert(cert)
        return Ok(None)
