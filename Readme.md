# Update script

This repository contains scripts related to the REST-API update endpoint of the Eltako Series 62 devices.

* client.py is a command line client that supports all relevant update commands
* rest_api.py is a library which can be used to write own clients. 

## client.py

The client script can be used to update a device or renew a device certificate.
In the following we assume that the device has the ip address `192.168.4.1` and the update server is running on `update.eltako.com` and is reachable on port `443` using `https`.
We use the ip address `192.168.4.1` on purpose since that is the one that is used when the device is not connected to a wifi yet.
This makes it possible to update devices prior commissioning.

### Updating

Updating a device is a multi-step process:

1. Retrieve authentication data of the device (`info`)
2. Check for new firmware versions (`check`)
3. Download new firmware versions (`fetch`)
4. Upload firmware to the device (`update`)

Commands further down either take the output of the previous commands from the command line or do them again.
The following will only fetch the authentication information, store it in a file `auth.bin` and print the information to the console.

```bash
./client.py --device 192.168.4.1 --no-verify --server https://update.eltako.com info --auth auth.bin
```

If you have mDNS enabled or your router adds the devices hostname to your standard DNS, then you can also use https:

```bash
./client.py --device eltako-<serial of your device> --ca path/to/eltako/user/api/certificates --server https://update.eltako.com info --auth auth.bin
```

The certificates bundle can be obtained from [https://github.com/Eltako/certificate-authority](https://github.com/Eltako/certificate-authority).

The file `auth.bin` can be used in all other commands.

From now on we assume that you're using secured communication.
In order to fetch the next version we can use the fetch command without checking for updates first.

```bash
./client.py --device eltako-<serial of your device> --ca  path/to/eltako/user/api/certificates --server https://update.eltako.com fetch --auth auth.bin -f fw.bin 
```

We may update the device using the file fw.bin:

```bash
./client.py --device eltako-<serial of your device> --ca  path/to/eltako/user/api/certificates --server https://update.eltako.com update -f fw.bin
```

It is also possible to do everything in a single command.
However, if we forget to specify the server uri we'll get an error message:

```bash
./client.py --device eltako-<serial of your device> --ca  path/to/eltako/user/api/certificates update
Error: Need server uri to fetch available versions from update server
```

Let's add it to the command line:

```bash
./client.py --device eltako-<serial of your device> --ca  path/to/eltako/user/api/certificates --server https://update.eltako.com update
```

### Advanced Usage

Since we can store the authentication data, we can also do updates later in case we don't have access to the internet.
In that case you may wish to download all available versions.
Use the `check` command to retrieve a list of available versions.
You may then download and store each version separately.


## Contribute

### Getting started

Clone this repository:

```bash
git clone https://github.com/Eltako/series62ip-updater
```

Start developing by installing the development version:

```bash
python setup.py develop
```

You can now edit the files and the change will instantly become visible in your system.


### Packaging

We follow [python-packaging](https://python-packaging.readthedocs.io/en/latest/index.html).