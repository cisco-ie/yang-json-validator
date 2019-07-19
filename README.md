# YANG JSON Validator
> Validate support for JSON based on YANG module support from Cisco devices.

This repository supplies `validate.py` and `validate_online.py` which consume a supplied YANG-based JSON file, containing configuration or operational data, and validate whether the elements present are supported. The reports generated detail what is implemented versus what is missing. This is important for identifying whether a model-based configuration is valid and supported.

## Installation
If Offline Validator is being used, this repository requires the Cisco YANG modules on GitHub to be located somewhere on your machine. `setup.sh` is provided for convenience to download a fixed/vetted fork of the models on GitHub.

Being a Python project, there will be some dependency installation necessary. [Pipenv](https://docs.pipenv.org/en/latest/#install-pipenv-today) is recommended and assumed.

```bash
./setup.sh
# Or manually...
# If you don't have pipenv, handle requirements.txt however you'd like.
git clone https://github.com/cisco-ie/yang -b fix-ietf-types-cisco
pipenv --three install
```

## Usage
These programs include command-line options as well as interactive selection interfaces. A convenience template of YANG-based JSON is supplied as `yang.json.example`.

### Online Validator
The online validator, `validate_online.py`, will connect to a network device over NETCONF, download all advertised YANG modules from the device, and validate the YANG JSON against the downloaded YANG modules. __This DOES NOT validate that the configuration itself is valid, simply that the elements referenced are theoretically supported.__

You may supply `-json_file` argument to indicate where the JSON to validate is located, `-report_file` to direct where the report will be stored, and `-online_config_json` for automated usage. A convenience template is supplied as `online_config.json.example`. If `-online_config_json` is not specified then an interactive selection interface will guide program usage.

```
bash-3.2$ pipenv run python validate_online.py --help
usage: validate_online.py [-h] [-json_file JSON_FILE]
                          [-report_file REPORT_FILE]
                          [-online_config_json [ONLINE_CONFIG_JSON]]

YANG JSON Validator against Online Device

optional arguments:
  -h, --help            show this help message and exit
  -json_file JSON_FILE  JSON to validate against YANG implementation.
  -report_file REPORT_FILE
                        Filename to output validation report.
  -online_config_json [ONLINE_CONFIG_JSON]
                        The JSON config file with connection details to the
                        live device.
```

### Offline Validator
The offline validator, `validate.py`, will attempt to validate the YANG JSON against the YANG modules found publicly in GitHub. This option does not require a live device to function. This option is inherently less guaranteed to be accurate due to not being sourced from a live device. If you believe there is some kind of error at hand, please raise a bug for review of the tool or the YANG modules on GitHub.

 If `-os`, `-release`, or `-product` (optional) are not supplied then the interactive interface will guide your usage. `-os`, `-release`, and `-product` follow the GitHub folder hierarchy. For example, `python validate.py -os xr -release 653`.

```bash
bash-3.2$ pipenv run python validate.py --help
usage: validate.py [-h] [-json_file JSON_FILE] [-report_file REPORT_FILE]
                   [-base_cisco_yang_path BASE_CISCO_YANG_PATH] [-os [OS]]
                   [-release [RELEASE]] [-product [PRODUCT]]

YANG JSON Validator

optional arguments:
  -h, --help            show this help message and exit
  -json_file JSON_FILE  JSON to validate against YANG implementation.
  -report_file REPORT_FILE
                        Filename to output validation report.
  -base_cisco_yang_path BASE_CISCO_YANG_PATH
                        The base file path containing the Cisco OS repo files.
  -os [OS]              Operating system to validate against.
  -release [RELEASE]    Release of OS to validate against.
  -product [PRODUCT]    Product of OS - Release to validate against.
```

## Example

### Input
`my_input.json`
```json
{
  "openconfig-acl:acl": {
    "acl-sets": {
      "acl-set": [
        {
          "acl-entries": {
            "acl-entry": [
              {
                "actions": {
                  "config": {
                    "forwarding-action": "openconfig-acl:ACCEPT"
                  }
                },
                "config": {
                  "sequence-id": 0
                },
                "ipv4": {
                  "config": {
                    "protocol": "openconfig-packet-match-types:IP_TCP"
                  }
                },
                "sequence-id": 0,
                "transport": {
                  "config": {
                    "destination-port": 80
                  }
                }
              }
            ]
          }
        }
      ]
    }
  },
  "openconfig-system:system": {
    "config": {
      "hostname": "friendly-yang"
    }
  }
}
```

### Command
```bash
pipenv shell
python validate.py -json_file my_input.json -os xr -release 653
```

### Output
`report.json`
```json
{
    "implemented": [
        "openconfig-acl:acl/acl-sets/acl-set/acl-entries/acl-entry/actions/config/forwarding-action",
        "openconfig-acl:acl/acl-sets/acl-set/acl-entries/acl-entry/config/sequence-id",
        "openconfig-acl:acl/acl-sets/acl-set/acl-entries/acl-entry/ipv4/config/protocol",
        "openconfig-acl:acl/acl-sets/acl-set/acl-entries/acl-entry/sequence-id",
        "openconfig-acl:acl/acl-sets/acl-set/acl-entries/acl-entry/transport/config/destination-port"
    ],
    "missing": [
        "openconfig-system:system/config/hostname"
    ]
}
```

## Licensing
This repository is licensed with [Apache License, Version 2.0](LICENSE).

## Limitations
1. Offline Validator does not validate "product" based on capabilities XML or hello messages. This means that current "product" evaluation is tentative at best.
2. Does not validate whether config elements match the associated primitive YANG types.
3. Does not attempt application of config to an online device to verify actual implementation support.
4. Does not distinguish between "missing" XPaths and XPaths which are accidentally invalid.
5. Does not indicate whether XPaths are explicitly missing or missing due to deviation, etc. (same goes for present/augmentation).

## Related Projects
The YANG parsing/comparison is largely derived from the work in [cisco-ie/tdm](https://github.com/cisco-ie/tdm) ETL which is derived from [pyang](https://github.com/mbj4668/pyang).
* [YANG Catalog](https://yangcatalog.org/)
* [YANG Modules](https://github.com/YangModels/yang)
* [Telemetry Data Mapper](https://github.com/cisco-ie/tdm)
* [Advanced NETCONF Explorer](https://github.com/cisco-ie/anx)
* [pyang](https://github.com/mbj4668/pyang)