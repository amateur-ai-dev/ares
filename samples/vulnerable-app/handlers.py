"""Request handling. Contains planted defects - see README."""

import pickle
import requests
import yaml
from jinja2 import Environment


def load_profile(blob):
    # CWE-502: arbitrary object construction from untrusted bytes
    return pickle.loads(blob)


def load_config(text):
    # CWE-502: yaml.load without SafeLoader
    return yaml.load(text)


def render(template_source, **context):
    # CWE-79: no autoescaping
    return Environment().from_string(template_source).render(**context)


def fetch(url):
    # CWE-295: encrypted but unauthenticated
    return requests.get(url, verify=False)


def run_rule(expression, row):
    # CWE-95: evaluation of a dynamic expression
    return eval(expression)
