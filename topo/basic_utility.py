import json
import yaml
from collections import OrderedDict



def is_power_of_two(n):
    return n > 0 and (n & (n - 1)) == 0


def save_proof_and_signatures_json(filename, proof_object, signatureA, signatureB, public_key):
    data_to_save = {
        'proof_object': proof_object,
        'signatureA': str(signatureA),
        'signatureB': str(signatureB),
        'public_key': str(public_key)
    }
    with open(filename, 'w') as f:
        json.dump(data_to_save, f, indent=4)


def load_proof_and_signatures_json(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    return data['proof_object'], data['signatureA'], data['signatureB'], data['public_key']


def print_in_red(text):
    # ANSI escape code for red text: \033[31m
    print(f"\033[31m{text}\033[0m")  # \033[0m resets the text to default color


def ordered_load(stream, Loader=yaml.SafeLoader, object_pairs_hook=OrderedDict):
    class OrderedLoader(Loader):
        pass

    def construct_mapping(loader, node):
        loader.flatten_mapping(node)
        return object_pairs_hook(loader.construct_pairs(node))

    OrderedLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
    return yaml.load(stream, OrderedLoader)


def ordered_dump(data, stream=None, Dumper=yaml.SafeDumper, **kwds):
    class OrderedDumper(Dumper):
        pass

    def _dict_representer(dumper, data):
        return dumper.represent_dict(data.items())

    OrderedDumper.add_representer(OrderedDict, _dict_representer)
    return yaml.dump(data, stream, OrderedDumper, **kwds)


# File discovery and key removal
def find_specific_entries(data, file_extensions=('.txt', '.dat')):
    results = []
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                results.extend(find_specific_entries(value, file_extensions))
            elif isinstance(value, str) and value.endswith(file_extensions):
                results.append(value)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                results.extend(find_specific_entries(item, file_extensions))
            elif isinstance(item, str) and item.endswith(file_extensions):
                results.append(item)
    return results


def remove_keys_recursive(data, exclude_keys):
    if isinstance(data, dict):
        return {k: remove_keys_recursive(v, exclude_keys) for k, v in data.items() if k not in exclude_keys}
    return data


def load_json(path):
    """
    Look for a .json file in extra args, and if found, load it.
    """
    try:
        with open(path, 'r') as f:
            data = json.load(f)
            return data
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading JSON file {path}: {e}")
        return {}
    return {}


