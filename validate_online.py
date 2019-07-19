#!/usr/bin/env python
"""Copyright 2019 Cisco Systems

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
"""This script will connect to a live device, download all YANG modules 
present on the device, compile the YANG schema, and compare a supplied
YANG-based JSON file to the schema to validate whether the supplied elements
are supported as advertised by the schema.
"""

import logging
import json
import argparse
import os
import re
import pyang
import PyInquirer
from ncclient import manager
from yang_json_validator import parse_repository, validate_modules


def main():
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("ncclient.operations.rpc").setLevel(logging.WARN)
    logging.getLogger("ncclient.transport.ssh").setLevel(logging.WARN)
    args = setup_args()
    validation_json = None
    try:
        with open(args.json_file, "r") as json_file_fd:
            validation_json = json.load(json_file_fd)
    except:
        logging.error("Ensure %s exists!", args.json_file)
        return 1
    report = {}
    if args.online_config_json:
        try:
            report = autopilot(args, validation_json)
        except:
            logging.exception("Error during autopilot! Abort abort.")
            return 2
    else:
        try:
            report = interactive_validation(args, validation_json)
        except:
            logging.exception("Error during interactive validation.")
            return 3
    write_report(report, args.report_file)
    return 0


def autopilot(args, validation_json):
    config = None
    try:
        with open(args.online_config_json, "r") as config_fd:
            config = json.load(config_fd)
    except:
        raise Exception("Error opening config %s!", args.online_config_json)
    return validate_online(validation_json, **config)


def interactive_validation(args, validation_json):
    """Derived from https://codeburst.io/building-beautiful-command-line-interfaces-with-python-26c7e1bb54df"""
    style = PyInquirer.style_from_dict(
        {
            PyInquirer.Token.Separator: "#cc5454",
            PyInquirer.Token.QuestionMark: "#673ab7 bold",
            PyInquirer.Token.Selected: "#cc5454",  # default
            PyInquirer.Token.Pointer: "#673ab7 bold",
            PyInquirer.Token.Instruction: "",  # default
            PyInquirer.Token.Answer: "#f44336 bold",
            PyInquirer.Token.Question: "",
        }
    )
    answers = {}
    questions = [
        {
            "type": "input",
            "name": "hostname",
            "message": "Device hostname to validate against?",
        },
        {
            "type": "list",
            "name": "device_type",
            "message": "Device type?",  # https://github.com/ncclient/ncclient#supported-device-handlers
            "choices": [
                "default",
                PyInquirer.Separator("= Cisco ="),
                "csr",
                "nexus",
                "iosxr",
                "iosxe",
                PyInquirer.Separator("= Juniper ="),
                "junos",
                PyInquirer.Separator("= Huawei ="),
                "huawei",
                "huaweiyang",
                PyInquirer.Separator("= Alcatel Lucent ="),
                "alu",
                PyInquirer.Separator("= H3C ="),
                "h3c",
                PyInquirer.Separator("= HP Comware ="),
                "hpcomware",
            ],
        },
        {"type": "input", "name": "username", "message": "Username?"},
        {"type": "password", "name": "password", "message": "Password?"},
    ]
    answers = PyInquirer.prompt(questions, style=style)
    return validate_online(validation_json, **answers)


def ensure_device_dir(hostname, base_dir="device_yang/"):
    if not os.path.isdir(base_dir):
        os.mkdir(base_dir)
    device_dir = os.path.join(base_dir, hostname)
    if not os.path.isdir(device_dir):
        os.mkdir(device_dir)
    return device_dir


def validate_online(validation_json, hostname, device_type, username, password):
    device_dir = ensure_device_dir(hostname)
    logging.info("Acquiring online device schemas to %s.", device_dir)
    download_device_schema(hostname, device_type, username, password, device_dir)
    logging.info("Parsing downloaded YANG modules ...")
    module_tree = parse_repository(device_dir)
    return run_validation_report(module_tree, validation_json)


def download_device_schema(
    hostname, device_type, username, password, schema_output_dir
):
    """Derived from https://github.com/CiscoDevNet/ncc/blob/master/ncc-get-all-schema"""
    schemas_filter = """<netconf-state xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
        <schemas>
            <schema>
                <identifier/>
            </schema>
        </schemas>
    </netconf-state>"""
    logging.info("Connecting to online device %s ...", hostname)
    with manager.connect(
        host=hostname, username=username, password=password, hostkey_verify=False
    ) as nc_mgr:
        schema_tree = nc_mgr.get(filter=("subtree", schemas_filter)).data
        schema_list = [
            n.text for n in schema_tree.xpath('//*[local-name()="identifier"]')
        ]
        not_in_schemas = set()
        logging.info("Parsing server capabilities ...")
        for c in nc_mgr.server_capabilities:
            model = re.search("module=([^&]*)", c)
            if model is not None:
                m = model.group(1)
                if m not in schema_list:
                    not_in_schemas.add(m)
                deviations = re.search("deviations=([^&<]*)", c)
                if deviations is not None:
                    d = deviations.group(1)
                    for dfn in d.split(","):
                        if dfn not in schema_list:
                            logging.debug("Deviation %s not in schema list", dfn)
                            not_in_schemas.add(dfn)
        if len(not_in_schemas) > 0:
            logging.error(
                "The following models are advertised in capabilities but are not in schemas tree:"
            )
            for m in sorted(not_in_schemas):
                logging.error("    {}".format(m))
        download_schemas(nc_mgr, schema_output_dir, schema_list)
        imports_and_includes = set()
        repos = pyang.FileRepository(schema_output_dir, use_env=False)
        ctx = pyang.Context(repos)
        yangfiles = [
            f
            for f in os.listdir(schema_output_dir)
            if os.path.isfile(os.path.join(schema_output_dir, f))
        ]
        for fname in sorted(yangfiles):
            logging.debug("Parsing %s", fname)
            with open(schema_output_dir + "/" + fname, "rb") as fd:
                text = fd.read().decode("UTF-8")
                ctx.add_module(fname, text)
                this_module = os.path.basename(fname).split(".")[0]
                for ((m, r), module) in ctx.modules.items():
                    if m == this_module:
                        for s in module.substmts:
                            if (s.keyword == "import") or (s.keyword == "include"):
                                imports_and_includes.add(s.arg)
        not_advertised = [str(i) for i in imports_and_includes if i not in schema_list]
        if len(not_advertised) > 0:
            logging.debug(
                "The following schema are imported or included, but not listed in schemas tree:"
            )
            for m in sorted(not_advertised, key=str.lower):
                logging.debug("    {}".format(m))
            download_schemas(nc_mgr, schema_output_dir, not_advertised)


def download_schemas(nc_mgr, schema_output_dir, schemas):
    logging.info("Downloading desired schemas to %s ...", schema_output_dir)
    for schema in schemas:
        schema_file_path = os.path.join(schema_output_dir, "%s.yang" % schema)
        if os.path.isfile(schema_file_path):
            logging.debug("Skipping %s", schema_file_path)
            continue
        content = None
        try:
            content = nc_mgr.get_schema(schema)
        except:
            logging.error("Failed to download schema %s", schema)
            continue
        with open(schema_file_path, "wb") as schema_fd:
            schema_fd.write(content.data.encode("utf-8"))


def run_validation_report(module_tree, validation_json):
    logging.info("Validating JSON against YANG module tree ...")
    implemented, missing = validate_modules(module_tree, validation_json)
    logging.info(
        "%i/%i (%.2f%%) implemented!",
        len(implemented),
        len(implemented) + len(missing),
        (len(implemented) / (len(implemented) + len(missing))) * 100,
    )
    return {"implemented": sorted(list(implemented)), "missing": sorted(list(missing))}


def write_report(report, filename="report.json"):
    logging.info("Writing report to %s ...", filename)
    with open(filename, "w") as report_fd:
        json.dump(report, report_fd, sort_keys=True, indent=4)


def setup_args():
    parser = argparse.ArgumentParser(
        description="YANG JSON Validator against Online Device"
    )
    parser.add_argument(
        "-json_file",
        help="JSON to validate against YANG implementation.",
        default="yang.json",
    )
    parser.add_argument(
        "-report_file",
        help="Filename to output validation report.",
        default="report.json",
    )
    parser.add_argument(
        "-online_config_json",
        help="The JSON config file with connection details to the live device.",
        nargs="?",
    )
    return parser.parse_args()


if __name__ == "__main__":
    exit(main())
