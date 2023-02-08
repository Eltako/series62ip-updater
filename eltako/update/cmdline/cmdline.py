#!/usr/bin/env python3
from eltako.update.client import *
import argparse
import pathlib


def arg_parser() -> argparse.ArgumentParser:
    cmdline_parser = argparse.ArgumentParser(
        description="Command line interface to update devices using the Eltako update protocol")
    cmdline_parser.add_argument("--device", "-d", help="URI of the device. Needs --pop.", dest="device_uri", type=str)

    device_auth_parser = cmdline_parser.add_mutually_exclusive_group()
    device_auth_parser.add_argument("--pop", dest="pop", type=str,
                                    help="Proof of possession string necessary to communicate with the device")
    device_auth_parser.add_argument("--api-key", dest="api_key", type=str,
                                    help="Set api key to use to initiate the connection")

    cmdline_parser.add_argument("--timeout", type=int, dest="timeout", help="Timeout before we drop the connection",
                                default=60)
    cmdline_parser.add_argument("--server", "-s", type=str, dest="server_uri", help="URI of the update server",
                                default="https://update.eltako.com")
    cmdline_parser.add_argument("-v", "--verbose", action='count', dest="verbose", help="Verbosity", default=0)
    ssl_verify_parser = cmdline_parser.add_mutually_exclusive_group()
    ssl_verify_parser.add_argument("--no-verify", dest="ssl_verify", action='store_false',
                                   help="Don't verify ssl connections")
    ssl_verify_parser.add_argument("--ca", dest="ssl_verify", type=str, help="Verify using the user provided CA bundle")

    subparsers = cmdline_parser.add_subparsers(dest="command")

    info_parser: argparse.ArgumentParser = subparsers.add_parser('info',
                                                                 help="Retrieve device authentication data from device")
    info_parser.add_argument("--auth", type=pathlib.Path, dest="auth",
                             help="Path where the authentication data should be stored")

    check_parser: argparse.ArgumentParser = subparsers.add_parser('check',
                                                                  help="Check if updates are available for the device")
    check_parser.add_argument("--auth", type=pathlib.Path, dest="auth", help="Path to authentication data")

    fetch_parser: argparse.ArgumentParser = subparsers.add_parser('fetch', help="Retrieve update image from update server")
    fetch_parser.add_argument("--auth", type=pathlib.Path, dest="auth", help="Path to authentication data")
    fetch_parser.add_argument("--version", type=str, dest="version", help="Version to download.")
    fetch_parser.add_argument("-f", "--firmware", type=pathlib.Path, dest="firmware",
                              help="Path where the firmware update should be stored")

    update_parser: argparse.ArgumentParser = subparsers.add_parser('update', help="Update the device")
    update_parser.add_argument("--auth", type=pathlib.Path, dest="auth", help="Path to authentication data")
    update_parser.add_argument("--version", type=str, dest="version", help="Version to download.")
    update_parser.add_argument("-f", "--firmware", type=pathlib.Path, dest="firmware", help="Path to firmware update")
    update_mut_flag = update_parser.add_mutually_exclusive_group()
    update_mut_flag.add_argument("--no-metadata", action="store_true", dest="no_metadata", help="Only upload metadata")
    update_mut_flag.add_argument("--no-image", action="store_true", dest="no_image", help="Only upload firmware image")

    fetch_csr_parser: argparse.ArgumentParser = subparsers.add_parser('csr',
                                                                      help="Fetch a certificate signing request from device")
    fetch_csr_parser.add_argument("--csr", type=pathlib.Path, dest="csr",
                                  help="Path where the certificate signing request should be stored")

    fetch_cert_parser: argparse.ArgumentParser = subparsers.add_parser('cert',
                                                                       help="Fetch a new certificate for the device")
    fetch_cert_parser.add_argument("--auth", type=pathlib.Path, dest="auth", help="Path to authentication data")
    fetch_cert_parser.add_argument("--csr", type=pathlib.Path, dest="csr",
                                   help="Path to the certificate signing request of the device")
    fetch_cert_parser.add_argument("--cert", type=pathlib.Path, dest="cert",
                                   help="Path where the new certificate should be stored")

    update_cert_parser = subparsers.add_parser('renew', help="Renew the certificate of the device")
    update_cert_parser.add_argument("--auth", type=pathlib.Path, dest="auth", help="Path to authentication data")
    update_cert_parser.add_argument("--csr", type=pathlib.Path, dest="csr", help="Path to csr data")
    update_cert_parser.add_argument("--cert", type=pathlib.Path, dest="cert", help="Path to new certificate")

    return cmdline_parser

def main() -> None:
    cmdline_parser = arg_parser()
    parsed_args = cmdline_parser.parse_args()

    if parsed_args.verbose == 1:
        logging.basicConfig(level=logging.INFO, format="%(message)s")
    elif parsed_args.verbose > 1:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")

    if parsed_args.command is not None:
        client: Client = Client(parsed_args)
        try:
            result = {
                "info": client.get_update_info,
                "check": client.get_available_versions,
                "fetch": client.get_firmware_update,
                "update": client.update_device,
                "csr": client.get_csr,
                "cert": client.get_cert,
                "renew": client.renew_cert
            }[parsed_args.command](True)
            print("{}".format(result))
        except Exception as e:
            print("Error: {}".format(e), file=sys.stderr)
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
