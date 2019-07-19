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
"""Compares supplied YANG JSON dict to parsed schema."""


from .module_parser import ModuleParser
import logging


def validate_modules(module_tree, yang_json_dict, only_leaves=True):
    present = set()
    not_present = set()

    def traverse_missing(yang_json_tree, xpath_prefix):
        if isinstance(yang_json_tree, (list,)):
            for list_value in yang_json_tree:
                if isinstance(list_value, (dict,)):
                    traverse_missing(list_value, xpath_prefix)
        if isinstance(yang_json_tree, (dict,)):
            for element in yang_json_tree.keys():
                element_xpath = (
                    "{}/{}".format(xpath_prefix, element) if xpath_prefix else element
                )
                if not only_leaves or (
                    only_leaves and check_leaf(yang_json_tree[element])
                ):
                    not_present.add(element_xpath)
                if isinstance(yang_json_tree[element], (dict, list)):
                    traverse_missing(yang_json_tree[element], element_xpath)

    def validate_children(node_tree, yang_json_tree, xpath_prefix=""):
        if isinstance(yang_json_tree, (list,)):
            had_valid = False
            for list_value in yang_json_tree:
                if isinstance(list_value, (dict,)):
                    # Likely valid structure to traverse if not just pure values
                    had_valid = True
                    validate_children(node_tree, list_value, xpath_prefix=xpath_prefix)
                elif had_valid:
                    logging.warning(
                        "Encountered weird structure at %s, abort abort.", xpath_prefix
                    )
                    break
                else:
                    logging.debug("Ignoring list value at %s", xpath_prefix)
        elif isinstance(yang_json_tree, (dict,)):
            for element in yang_json_tree.keys():
                matched = False
                element_xpath = (
                    "{}/{}".format(xpath_prefix, element) if xpath_prefix else element
                )
                for xpath, module_element in node_tree.items():
                    if (
                        module_element["name"] == element
                        or module_element["prefixed_name"] == element
                    ):
                        matched = True
                        if not only_leaves or (
                            only_leaves and not module_element["children"]
                        ):
                            present.add(element_xpath)
                        if isinstance(yang_json_tree[element], (dict, list)):
                            validate_children(
                                module_element["children"],
                                yang_json_tree[element],
                                xpath_prefix=element_xpath,
                            )
                        break
                if not matched:
                    if not only_leaves or (
                        only_leaves and check_leaf(yang_json_tree[element])
                    ):
                        not_present.add(element_xpath)
                    if isinstance(yang_json_tree[element], (dict, list)):
                        traverse_missing(yang_json_tree[element], element_xpath)
        else:
            logging.warning("Unhandled type at %s!", xpath_prefix)

    module_top_children = {}
    for top_children in module_tree.values():
        module_top_children.update(top_children)
    validate_children(module_top_children, yang_json_dict)
    return reduce_xpath_set(present), reduce_xpath_set(not_present)


def check_leaf(element):
    return not isinstance(element, (dict, list))


def reduce_xpath_set(xpath_set):
    reduced_set = xpath_set.copy()
    handled = set()
    for element in sorted(xpath_set):
        for other_element in xpath_set:
            if other_element == element:
                continue
            if other_element in handled:
                continue
            if element.startswith(other_element):
                reduced_set.remove(other_element)
                handled.add(other_element)
    return reduced_set
