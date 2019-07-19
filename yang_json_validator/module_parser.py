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

"""YANG module parser, written to expect Cisco YANG modules.
Assumes directory structure of...
base_path/os/release/product
"""
import pdb
import os
import json
import logging
import shutil
import random
from . import yang_parser


class ModuleParser:
    def __init__(self, base_path="yang/vendor/cisco"):
        if not os.path.isdir(base_path):
            raise FileNotFoundError("%s does not exist!", base_path)
        self.os_release_prod_map = self.build_prod_tree(base_path)

    def build_prod_tree(self, base_path):
        tree = {}
        for os_dir in os.listdir(base_path):
            os_dir_path = os.path.join(base_path, os_dir)
            if not os.path.isdir(os_dir_path):
                continue
            tree[os_dir] = {"path": os_dir_path, "releases": {}}
            for release_dir in os.listdir(os_dir_path):
                release_dir_path = os.path.join(os_dir_path, release_dir)
                if not os.path.isdir(release_dir_path):
                    continue
                tree[os_dir]["releases"][release_dir] = {
                    "path": release_dir_path,
                    "products": {},
                }
                for product_dir in os.listdir(release_dir_path):
                    product_dir_path = os.path.join(release_dir_path, product_dir)
                    if (
                        not os.path.isdir(product_dir_path)
                        or product_dir == "MIBS"
                        or product_dir.endswith(".incompatible")
                    ):
                        continue
                    tree[os_dir]["releases"][release_dir]["products"][
                        product_dir
                    ] = product_dir_path
        return tree

    def parse_product(self, product_os, product_release, product_name=None):
        if product_os not in self.os_release_prod_map.keys():
            raise Exception("%s is not a supported OS!", product_os)
        if (
            product_release
            not in self.os_release_prod_map[product_os]["releases"].keys()
        ):
            raise Exception(
                "%s - %s is not a supported release!", product_os, product_release
            )
        release_attrs = self.os_release_prod_map[product_os]["releases"][
            product_release
        ]
        release_repo_path = release_attrs["path"]
        product_repo_path = None
        if not product_name:
            product_repo_path = release_repo_path
            if release_attrs["products"].keys():
                logging.warning(
                    "No product name specified but %s - %s contains products!",
                    product_os,
                    product_release,
                )
            logging.debug("Product %s - %s selected.", product_os, product_release)
        elif product_name in release_attrs["products"]:
            product_repo_path = release_attrs["products"][product_name]
            logging.debug(
                "Product %s - %s - %s selected.",
                product_os,
                product_release,
                product_name,
            )
        else:
            raise Exception(
                "%s - %s - %s is not a supported product!",
                product_os,
                product_release,
                product_name,
            )
        if product_repo_path != release_repo_path:
            self.ensure_product_release_files(release_repo_path, product_repo_path)
        return parse_repository(product_repo_path)

    def ensure_product_release_files(self, release_repo_path, product_repo_path):
        release_yang_files = {
            yang_file
            for yang_file in os.listdir(release_repo_path)
            if yang_file.endswith(".yang")
        }
        product_yang_files = {
            yang_file
            for yang_file in os.listdir(product_repo_path)
            if yang_file.endswith(".yang")
        }
        required_files = release_yang_files.difference(product_yang_files)
        for required_file in required_files:
            try:
                shutil.copy(
                    os.path.join(release_repo_path, required_file),
                    os.path.join(product_repo_path, required_file),
                )
            except shutil.SameFileError:
                logging.warning("%s already exists!", required_file)
        special_dirs = ["MIBS/"]
        for special_dir in special_dirs:
            release_special_path = os.path.join(release_repo_path, special_dir)
            product_special_path = os.path.join(product_repo_path, special_dir)
            if os.path.isdir(product_special_path):
                continue
            if os.path.isdir(release_special_path):
                shutil.copytree(release_special_path, product_special_path)


def parse_repository(repo_path):
    modules = yang_parser.parse_repository(repo_path)
    parsed_modules = {}
    for module_key, module_revision in modules.items():
        revision_with_data = set()
        for revision_key, module in module_revision.items():
            revision_data = None
            try:
                revision_data = __parse_node_attrs(module)
            except Exception:
                logging.exception("Failure while parsing %s!", module_key)
            if not revision_data:
                logging.debug("%s@%s is empty.", module_key, revision_key)
                continue
            revision_with_data.add("%s@%s" % (module_key, revision_key))
            if module_key in parsed_modules.keys() and parsed_modules[module_key]:
                logging.warn(
                    "%s being replaced with %s@%s! Only one revision should be used.",
                    module_key,
                    module_key,
                    revision_key,
                )
            parsed_modules[module_key] = revision_data
        if revision_with_data:
            logging.debug("%s have data.", ", ".join(revision_with_data))
        else:
            logging.debug("%s has no revisions with data.", module_key)
    return parsed_modules


def __parse_node_attrs(node):
    if not hasattr(node, "i_children"):
        return {}
    children = (
        child
        for child in node.i_children
        if child.keyword in yang_parser.statements.data_definition_keywords
    )
    parsed_children = {}
    multi_map = {}
    for child in children:
        qualified_xpath = yang_parser.get_xpath(
            child, qualified=True, prefix_to_module=True
        )
        if qualified_xpath in parsed_children.keys():
            logging.error("%s encountered more than once! Muxing." % qualified_xpath)
            if qualified_xpath not in multi_map.keys():
                multi_map[qualified_xpath] = 0
            multi_map[qualified_xpath] += 1
            qualified_xpath += "_%i" % multi_map[qualified_xpath]
        attr_dict = {
            "name": child.arg,
            "prefixed_name": qualified_xpath
            if "/" not in qualified_xpath
            else qualified_xpath[qualified_xpath.rindex("/") + 1 :],
            "qualified_xpath": qualified_xpath,
            "xpath": yang_parser.get_xpath(child, prefix_to_module=True),
            "primitive_type": yang_parser.get_primitive_type(child),
            "rw": True if getattr(child, "i_config", False) else False,
            "children": __parse_node_attrs(child),
        }
        parsed_children[qualified_xpath] = attr_dict
    return parsed_children
