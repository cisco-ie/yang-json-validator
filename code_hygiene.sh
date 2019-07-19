#!/usr/bin/env bash
pipenv run black --safe --verbose *.py yang_json_validator/
pipenv run pylint *.py yang_json_validator/