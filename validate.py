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
"""This script will compile the YANG schema from a directory of YANG modules
and compare a supplied YANG-based JSON file to the schema to validate whether
the supplied elements are supported as advertised by the schema.
"""


import logging
import json
import argparse
import PyInquirer
from yang_json_validator import ModuleParser, validate_modules


def main():
    logging.basicConfig(level=logging.INFO)
    args = setup_args()
    module_parser = None
    try:
        module_parser = ModuleParser(args.base_cisco_yang_path)
    except FileNotFoundError:
        logging.error("Ensure %s exists!", args.base_cisco_yang_path)
        return 1
    validation_json = None
    try:
        with open(args.json_file, "r") as json_file_fd:
            validation_json = json.load(json_file_fd)
    except:
        logging.error("Ensure %s exists!", args.json_file)
        return 2
    report = {}
    if args.os or args.release or args.product:
        try:
            report = autopilot(args, validation_json, module_parser)
        except:
            logging.exception("Error during autopilot! Abort abort.")
            return 3
    else:
        try:
            report = interactive_validation(args, validation_json, module_parser)
        except:
            logging.exception("Error during interactive validation.")
            return 4
    write_report(report, args.report_file)
    return 0


def autopilot(args, validation_json, module_parser):
    if not args.os:
        raise Exception("OS must be specified!")
    elif not args.release:
        raise Exception("Release must be specified!")
    return validate_product(
        module_parser, validation_json, args.os, args.release, args.product
    )


def interactive_validation(args, validation_json, module_parser):
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

    def get_os_releases(answers):
        return sorted(
            list(module_parser.os_release_prod_map[answers["os"]]["releases"].keys()),
            reverse=True,
        )

    def get_os_release_products(answers):
        return sorted(
            ["None"]
            + list(
                module_parser.os_release_prod_map[answers["os"]]["releases"][
                    answers["release"]
                ]["products"].keys()
            )
        )

    questions = [
        {
            "type": "list",
            "name": "os",
            "message": "Which OS to validate against?",
            "choices": sorted(list(module_parser.os_release_prod_map.keys())),
            "filter": lambda val: val.lower(),
        },
        {
            "type": "list",
            "name": "release",
            "message": "Which Release of OS?",
            "choices": get_os_releases,
        },
        {
            "type": "list",
            "name": "product",
            "message": "Which Product of OS - Release?",
            "choices": get_os_release_products,
        },
    ]
    answers = PyInquirer.prompt(questions, style=style)
    return validate_product(
        module_parser,
        validation_json,
        answers["os"],
        answers["release"],
        None if answers["product"] == "None" else answers["product"],
    )


def validate_product(
    module_parser, validation_json, product_os, product_release, product_name=None
):
    logging.info("Parsing %s - %s - %s ...", product_os, product_release, product_name)
    module_tree = module_parser.parse_product(product_os, product_release, product_name)
    return run_validation_report(module_tree, validation_json)


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
    parser = argparse.ArgumentParser(description="YANG JSON Validator")
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
        "-base_cisco_yang_path",
        help="The base file path containing the Cisco OS repo files.",
        default="yang/vendor/cisco",
    )
    parser.add_argument("-os", help="Operating system to validate against.", nargs="?")
    parser.add_argument(
        "-release", help="Release of OS to validate against.", nargs="?"
    )
    parser.add_argument(
        "-product", help="Product of OS - Release to validate against.", nargs="?"
    )
    return parser.parse_args()


if __name__ == "__main__":
    exit(main())
