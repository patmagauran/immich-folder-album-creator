#1. Get all assets
#2. If the asset's original path is the root of a base folder continue
#3. Separate out desired path
#4. Get tags
#5. Associate existing tags to folder mappings. Figure out what tags need to be created
#6. Create needed tags and add ids
#7. Create list of assets that need a new tag
#8. Create list of assets that need their tag changed. (I am not sure if this can actually happen as the process for a moved external file is create / delete, so this info would be lost...)
#9. Essentially, if any of the existing tags are in the search folders but not what we want, remove it
# i.e if value != (Desired segment of root path)




"""Python script for creating Tags in Immich from folder names in an external library."""

from typing import Tuple
import argparse
import logging
import sys
import os
import datetime
from collections import defaultdict, OrderedDict
from urllib.error import HTTPError

import regex

import urllib3
import requests

# Script Constants

# Constants holding script run modes
# Create tags based on folder names and script arguments
SCRIPT_MODE_CREATE = "CREATE"


# Environment variable to check if the script is running inside Docker
ENV_IS_DOCKER = "IS_DOCKER"

# Immich API request timeout
REQUEST_TIMEOUT_DEFAULT = 20

def identify_root_path(path: str, root_path_list: list[str]) -> str:
    """
    Identifies which root path is the parent of the provided path.
    
    :param path: The path to find the root path for
    :type path: str
    :param root_path_list: The list of root paths to get the one path is a child of from
    :type root_path_list: list[str]
    :return: The root path from root_path_list that is the parent of path
    :rtype: str
    """
    for root_path in root_path_list:
        if root_path in path:
            return root_path
    return None



def is_integer(string_to_test: str) -> bool:
    """ 
    Trying to deal with python's isnumeric() function
    not recognizing negative numbers, tests whether the provided 
    string is an integer or not.

    Parameters
    ----------
        string_to_test : str
            The string to test for integer
    Returns
    ---------
        True if string_to_test is an integer, otherwise False
    """
    try:
        int(string_to_test)
        return True
    except ValueError:
        return False

# Translation of GLOB-style patterns to Regex
# Source: https://stackoverflow.com/a/63212852
# FIXME_EVENTUALLY: Replace with glob.translate() introduced with Python 3.13
escaped_glob_tokens_to_re = OrderedDict((
    # Order of ``**/`` and ``/**`` in RE tokenization pattern doesn't matter because ``**/`` will be caught first no matter what, making ``/**`` the only option later on.
    # W/o leading or trailing ``/`` two consecutive asterisks will be treated as literals.
    ('/\\*\\*', '(?:/.+?)*'), # Edge-case #1. Catches recursive globs in the middle of path. Requires edge case #2 handled after this case.
    ('\\*\\*/', '(?:^.+?/)*'), # Edge-case #2. Catches recursive globs at the start of path. Requires edge case #1 handled before this case. ``^`` is used to ensure proper location for ``**/``.
    ('\\*', '[^/]*'), # ``[^/]*`` is used to ensure that ``*`` won't match subdirs, as with naive ``.*?`` solution.
    ('\\?', '.'),
    ('\\[\\*\\]', '\\*'), # Escaped special glob character.
    ('\\[\\?\\]', '\\?'), # Escaped special glob character.
    ('\\[!', '[^'), # Requires ordered dict, so that ``\\[!`` preceded ``\\[`` in RE pattern.
                    # Needed mostly to differentiate between ``!`` used within character class ``[]`` and outside of it, to avoid faulty conversion.
    ('\\[', '['),
    ('\\]', ']'),
))

escaped_glob_replacement = regex.compile('(%s)' % '|'.join(escaped_glob_tokens_to_re).replace('\\', '\\\\\\'))

def glob_to_re(pattern: str) -> str:
    """ 
    Converts the provided GLOB pattern to
    a regular expression.

    Parameters
    ----------
        pattern : str
            A GLOB-style pattern to convert to a regular expression
    Returns
    ---------
        A regular expression matching the same strings as the provided GLOB pattern
    """
    return escaped_glob_replacement.sub(lambda match: escaped_glob_tokens_to_re[match.group(0)], regex.escape(pattern))

def read_file(file_path: str) -> str:
    """ 
    Reads and returns the contents of the provided file.

    Parameters
    ----------
        file_path : str
            Path to the file to read
    Raises
    ----------
        FileNotFoundError if the file does not exist
        Exception on any other error reading the file
    Returns
    ---------
        The file's contents
    """
    with open(file_path, 'r', encoding="utf-8") as secret_file:
        return secret_file.read().strip()

def read_api_key_from_file(file_path: str) -> str:
    """ 
    Reads the API key from the provided file

    Parameters
    ----------
        file_path : str
            Path to the file to read
    Returns
    ---------
        The API key or None on error
    """
    try:
        return read_file(file_path)
    except FileNotFoundError:
        logging.error("API Key file not found at %s", args["api_key"])
    except OSError as ex:
        logging.error("Error reading API Key file: %s", ex)
    return None

def determine_api_key(api_key_source: str, key_type: str) -> str:
    """ 
    Determines the API key base on key_type.
    For key_type 'literal', api_key_source is returned as is.
    For key'type 'file', api_key_source is a path to a file containing the API key,
    and the file's contents are returned.

    Parameters
    ----------
        api_key_source : str
            An API key or path to a file containing an API key
        key_type : str
            Must be either 'literal' or 'file'
    Returns
    ---------
        The API key or None on error
    """
    if key_type == 'literal':
        return api_key_source
    if key_type == 'file':
        return read_file(api_key_source)
    # At this point key_type is not a valid value
    logging.error("Unknown key type (-t, --key-type). Must be either 'literal' or 'file'.")
    return None

def expand_to_glob(expr: str) -> str:
    """ 
    Expands the passed expression to a glob-style
    expression if it doesn't contain neither a slash nor an asterisk.
    The resulting glob-style expression matches any path that contains the 
    original expression anywhere.

    Parameters
    ----------
        expr : str
            Expression to expand to a GLOB-style expression if not already
            one
    Returns
    ---------
        The original expression if it contained a slash or an asterisk,
        otherwise \\*\\*/\\*\\<expr\\>\\*/\\*\\*
    """
    if not '/' in expr and not '*' in expr:
        glob_expr = f'**/*{expr}*/**'
        logging.debug("expanding %s to %s", expr, glob_expr)
        return glob_expr
    return expr

def divide_chunks(full_list: list, chunk_size: int):
    """Yield successive n-sized chunks from l. """
    # looping till length l
    for j in range(0, len(full_list), chunk_size):
        yield full_list[j:j + chunk_size]

def parse_separated_string(separated_string: str, separator: str) -> Tuple[str, str]:
    """
    Parse a key, value pair, separated by the provided separator.
    
    That's the reverse of ShellArgs.
    On the command line (argparse) a declaration will typically look like:
        foo=hello
    or
        foo="hello world"
    """
    items = separated_string.split(separator)
    key = items[0].strip() # we remove blanks around keys, as is logical
    value = None
    if len(items) > 1:
        # rejoin the rest:
        value = separator.join(items[1:])
    return (key, value)


def parse_separated_strings(items: list[str]) -> dict:
    """
    Parse a series of key-value pairs and return a dictionary
    """
    parsed_strings_dict = {}
    if items:
        for item in items:
            key, value = parse_separated_string(item, '=')
            parsed_strings_dict[key] = value
    return parsed_strings_dict


def is_path_ignored(path_to_check: str) -> bool:
    """
    Determines if the asset should be ignored for the purpose of this script
    based in its originalPath and global ignore and path_filter options.

    Parameters
    ----------
        asset_to_check : dict
            The asset to check if it must be ignored or not. Must have the key 'originalPath'.
    Returns 
    ----------
        True if the asset must be ignored, otherwise False
    """
    is_path_ignored_result = False
    asset_root_path = None
    for root_path_to_check in root_paths:
        if root_path_to_check in path_to_check:
            asset_root_path = root_path_to_check
            break
    logging.debug("Identified root_path for asset %s = %s", path_to_check, asset_root_path)
    if asset_root_path:
        # First apply filter, if any
        if len(path_filter_regex) > 0:
            any_match = False
            for path_filter_regex_entry in path_filter_regex:
                if regex.fullmatch(path_filter_regex_entry, path_to_check.replace(asset_root_path, '')):
                    any_match = True
            if not any_match:
                logging.debug("Ignoring path %s due to path_filter setting!", path_to_check)
                is_path_ignored_result = True
        # If the asset "survived" the path filter, check if it is in the ignore_tags argument
        if not is_path_ignored_result and len(ignore_tags_regex) > 0:
            for ignore_tags_regex_entry in ignore_tags_regex:
                if regex.fullmatch(ignore_tags_regex_entry, path_to_check.replace(asset_root_path, '')):
                    is_path_ignored_result = True
                    logging.debug("Ignoring path %s due to ignore_tags setting!", path_to_check)
                    break

    return is_path_ignored_result


# pylint: disable=R0912
def create_tag_name(asset_path_chunks: list[str], tag_name_postprocess_regex: list, base_tag: str) -> str:
    """
    Create tag names from provided path_chunks string array.

    The method uses global variables tag_levels_range_arr or tag_levels to
    generate tag names either by level range or absolute tag levels. If multiple
    tag path chunks are used for tag names they are separated by tag_separator.

    tag_name_postprocess_regex is list of pairs of regex and replace, this is optional
    """

    tag_name_chunks = ()
    logging.debug("path chunks = %s", list(asset_path_chunks))
    # Check which path to take: tag_levels_range or tag_levels
    if len(tag_levels_range_arr) == 2:
        if tag_levels_range_arr[0] < 0:
            tag_levels_start_level_capped = min(len(asset_path_chunks), abs(tag_levels_range_arr[0]))
            tag_levels_end_level_capped =  tag_levels_range_arr[1]+1
            tag_levels_start_level_capped *= -1
        else:
            tag_levels_start_level_capped = min(len(asset_path_chunks)-1, tag_levels_range_arr[0])
            # Add 1 to tag_levels_end_level_capped to include the end index, which is what the user intended to. It's not a problem
            # if the end index is out of bounds.
            tag_levels_end_level_capped =  min(len(asset_path_chunks)-1, tag_levels_range_arr[1]) + 1
        logging.debug("tag_levels_start_level_capped = %d", tag_levels_start_level_capped)
        logging.debug("tag_levels_end_level_capped = %d", tag_levels_end_level_capped)
        # tag start level is not equal to tag end level, so we want a range of levels
        if tag_levels_start_level_capped is not tag_levels_end_level_capped:

            # if the end index is out of bounds.
            if tag_levels_end_level_capped < 0 and abs(tag_levels_end_level_capped) >= len(asset_path_chunks):
                tag_name_chunks = asset_path_chunks[tag_levels_start_level_capped:]
            else:
                tag_name_chunks = asset_path_chunks[tag_levels_start_level_capped:tag_levels_end_level_capped]
        # tag start and end levels are equal, we want exactly that level
        else:
            # create on-the-fly array with a single element taken from
            tag_name_chunks = [asset_path_chunks[tag_levels_start_level_capped]]
    else:
        tag_levels_int = int(tag_levels)
        # either use as many path chunks as we have,
        # or the specified tag levels
        tag_name_chunk_size = min(len(asset_path_chunks), abs(tag_levels_int))
        if tag_levels_int < 0:
            tag_name_chunk_size *= -1

        # Copy tag name chunks from the path to use as tag name
        tag_name_chunks = asset_path_chunks[:tag_name_chunk_size]
        if tag_name_chunk_size < 0:
            tag_name_chunks = asset_path_chunks[tag_name_chunk_size:]
    logging.debug("tag_name_chunks = %s", tag_name_chunks)

    # final tag name before regex
    if base_tag != '':
        tag_name_chunks.insert(0, base_tag)
    tag_name = '/'.join(tag_name_chunks)
    logging.debug("tag Name %s", tag_name)

    # apply regex if any
    if tag_name_postprocess_regex:
        for pattern, *repl in tag_name_postprocess_regex:
            # If no replacement string provided, default to empty string
            replace = repl[0] if repl else ''
            tag_name = regex.sub(pattern, replace, tag_name)
            logging.debug("tag Post Regex s/%s/%s/g --> %s", pattern, replace, tag_name)

    return tag_name.strip()

def build_tag_list(asset_list : list[dict], root_path_list : list[str], base_tag_list : list[str]) -> dict:
    """
    Builds a list of tags and their assets.
    Returns a dict where the key is the tag name and the value is list of assets.
    Attention!

    Parameters
    ----------
        asset_list : list[dict]
            List of assets dictionaries fetched from Immich API
        root_path_list : list[str]
            List of root paths to use for album creation
        base_tag_list: list[str]
            list of base tag names to use corresponding to the root paths

    Returns
    ---------
        A dict with tag names as keys and asset ids as values
    """
    tag_dict = defaultdict(list)
    base_tag = ""
    for asset_to_add in asset_list:
        asset_path = asset_to_add['originalPath']
        # This method will log the ignore reason, so no need to log anything again.
        if is_path_ignored(asset_path):
            continue

        # Identify the root path
        asset_root_path = identify_root_path(asset_path, root_path_list)
        if not asset_root_path:
            continue
        if len(base_tag_list) == 1:
            base_tag = base_tag_list[0].strip()
        elif len(base_tag_list) > 1:
            base_tag = base_tag_list[root_path_list.index(asset_root_path)].strip()
        # Chunks of the asset's path below root_path
        path_chunks = asset_path.replace(asset_root_path, '').split('/')
        # A single chunk means it's just the image file in no sub folder, ignore
        if len(path_chunks) == 1:
            continue

        # remove last item from path chunks, which is the file name
        del path_chunks[-1]
        tag_name = create_tag_name(path_chunks, tag_name_post_regex,base_tag)
        if len(tag_name) > 0:
            # Add asset to tag model, but only if it is new
            should_add_asset = True
            if 'tags' in asset_to_add:
                for tag in asset_to_add['tags']:
                    if 'value' in tag and tag['value'] == tag_name:
                        should_add_asset = False
            if should_add_asset:
                if tag_name in tag_dict:
                    tag_dict[tag_name].append(asset_to_add['id'])
                else:
                    tag_dict[tag_name] = [asset_to_add['id']]
        else:
            logging.warning("Got empty tag name for asset path %s, check your tag_level settings!", asset_path)

    return tag_dict

def check_api_response(response: requests.Response):
    """
    Checks the HTTP return code for the provided response and
    logs any errors before raising an HTTPError

    Parameters
    ----------
        response : requests.Response
            A list of asset IDs to archive
        isArchived : bool
            Flag indicating whether to archive or unarchive the passed assets
   
    Raises
    ----------
        HTTPError if the API call fails
    """
    try:
        response.raise_for_status()
    except HTTPError:
        if response.json():
            logging.error("Error in API call: %s", response.json())
        else:
            logging.error("API response did not contain a payload")
    response.raise_for_status()


def fetch_server_version() -> dict:
    """
    Fetches the API version from the immich server.

    If the API endpoint for getting the server version cannot be reached,
    raises HTTPError
    
    Returns
    -------
        Dictionary with keys 
            - major
            - minor
            - patch
    """
    api_endpoint = f'{root_url}server/version'
    r = requests.get(api_endpoint, **requests_kwargs, timeout=api_timeout)
    # The API endpoint changed in Immich v1.118.0, if the new endpoint
    # was not found try the legacy one
    if r.status_code == 404:
        api_endpoint = f'{root_url}server-info/version'
        r = requests.get(api_endpoint, **requests_kwargs, timeout=api_timeout)

    if r.status_code == 200:
        server_version = r.json()
        logging.info("Detected Immich server version %s.%s.%s", server_version['major'], server_version['minor'], server_version['patch'])
    # Any other errors mean communication error with API
    else:
        logging.error("Communication with Immich API failed! Make sure the passed API URL is correct!")
        check_api_response(r)
    return server_version


def fetch_assets(is_not_in_tag: bool, find_archived: bool) -> list:
    """
    Fetches assets from the Immich API.

    Uses the /search/meta-data call. Much more efficient than the legacy method
    since this call allows to filter for assets that are not in an tag only.
    
    Parameters
    ----------
        is_not_in_tag : bool
            Flag indicating whether to fetch only assets that are not part
            of an tag or not. If set to False, will find images in tags and 
            not part of tags
        find_archived : bool
            Flag indicating whether to only fetch assets that are archived. If set to False,
            will find archived and unarchived images
    Returns
    ---------
        An array of asset objects
    """

    return fetch_assets_with_options({'isNotIntag': is_not_in_tag, 'withArchived': find_archived})

def fetch_assets_with_options(search_options: dict) -> list:
    """
    Fetches assets from the Immich API using specific search options.
    The search options directly correspond to the body used for the search API request.
    
    Parameters
    ----------
        search_options: dict
            Dictionary containing options to pass to the search/metadata API endpoint
    Returns
    ---------
        An array of asset objects
    """
    body = search_options
    assets_found = []
    # prepare request body

    # This API call allows a maximum page size of 1000
    number_of_assets_to_fetch_per_request_search = min(1000, number_of_assets_to_fetch_per_request)
    body['size'] = number_of_assets_to_fetch_per_request_search
    # Initial API call, let's fetch our first chunk
    page = 1
    body['page'] = str(page)
    r = requests.post(root_url+'search/metadata', json=body, **requests_kwargs, timeout=api_timeout)
    r.raise_for_status()
    response_json = r.json()
    assets_received = response_json['assets']['items']
    logging.debug("Received %s assets with chunk %s", len(assets_received), page)

    assets_found = assets_found + assets_received
    # If we got a full chunk size back, let's perform subsequent calls until we get less than a full chunk size
    while len(assets_received) == number_of_assets_to_fetch_per_request_search:
        page += 1
        body['page'] = page
        r = requests.post(root_url+'search/metadata', json=body, **requests_kwargs, timeout=api_timeout)
        check_api_response(r)
        response_json = r.json()
        assets_received = response_json['assets']['items']
        logging.debug("Received %s assets with chunk %s", len(assets_received), page)
        assets_found = assets_found + assets_received
    return assets_found


def fetch_tags():
    """Fetches tags from the Immich API"""

    api_endpoint = 'tags'

    r = requests.get(root_url+api_endpoint, **requests_kwargs, timeout=api_timeout)
    check_api_response(r)
    return r.json()



def add_assets_to_tag(assets_add_tag_id: str, asset_list: list[str]) -> list[str]:
    """
    Adds the assets IDs provided in assets to the provided tagId.

    If assets if larger than number_of_images_per_request, the list is chunked
    and one API call is performed per chunk.
    Only logs errors and successes.

    Returns 

    Parameters
    ----------
        assets_add_tag_id : str
            The ID of the tag to add assets to
        asset_list: list[str]
            A list of asset IDs to add to the tag

    Returns
    ---------
        The asset UUIDs that were actually added to the tag (not respecting assets that were already part of the tag)
    """
    api_endpoint = 'tags'

    # Divide our assets into chunks of number_of_images_per_request,
    # So the API can cope
    assets_chunked = list(divide_chunks(asset_list, number_of_images_per_request))
    asset_list_added = []
    for assets_chunk in assets_chunked:
        data = {'ids':assets_chunk}
        r = requests.put(root_url+api_endpoint+f'/{assets_add_tag_id}/assets', json=data, **requests_kwargs, timeout=api_timeout)
        check_api_response(r)
        response = r.json()

        for res in response:
            if not res['success']:
                if  res['error'] != 'duplicate':
                    logging.warning("Error adding an asset to an tag: %s", res['error'])
            else:
                asset_list_added.append(res['id'])

    return asset_list_added


def create_tag(tag_path: str) -> str:
    """
    Creates a tag with the provided name and returns the ID of the created tag
    

    Parameters
    ----------
        tag_name_to_create : str
            Name of the tag to create

    Returns
    ---------
        True if the tag was deleted, otherwise False
    
    Raises
    ----------
        Exception if the API call failed
    """

    api_endpoint = 'tags'

    data = {
        'tags': [tag_path]
    }
    r = requests.put(root_url+api_endpoint, json=data, **requests_kwargs, timeout=api_timeout)
    check_api_response(r)

    return r.json()[0]['id']




parser = argparse.ArgumentParser(description="Create Immich Tags from an external library path based on the top level folders",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("root_path", action='append', help="The external library's root path in Immich")
parser.add_argument("api_url", help="The root API URL of immich, e.g. https://immich.mydomain.com/api/")
parser.add_argument("api_key", help="The Immich API Key to use. Set --api-key-type to 'file' if a file path is provided.")
parser.add_argument("-a", "--api-key-type", default="literal", choices=['literal', 'file'], help="The type of the Immich API Key")
parser.add_argument("-r", "--root-path", action="append",
                    help="Additional external library root path in Immich; May be specified multiple times for multiple import paths or external libraries.")
parser.add_argument("-b", "--base-tag", action="append",
                    help="A base tag to use for the tag hierarchy. Can be specified as a single tag for all root paths or one per(Processed in the same order as root paths are provided)")
parser.add_argument("-u", "--unattended", action="store_true", help="Do not ask for user confirmation after identifying tags. Set this flag to run script as a cronjob.")
parser.add_argument("-t", "--tag-levels", default="1", type=str,
                    help="""Number of sub-folders or range of sub-folder levels below the root path used for tag name creation.
                            Positive numbers start from top of the folder structure, negative numbers from the bottom. Cannot be 0. 
                            If a range should be set, the start level and end level must be separated by a comma like '<startLevel>,<endLevel>'. 
                            If negative levels are used in a range, <startLevel> must be less than or equal to <endLevel>.""")

parser.add_argument("-R", "--tag-name-post-regex", nargs='+',
        action='append',
        metavar=('PATTERN', 'REPL'),
        help='Regex pattern and optional replacement (use "" for empty replacement). Can be specified multiple times.')
parser.add_argument("-c", "--chunk-size", default=2000, type=int, help="Maximum number of assets to add to an tag with a single API call")
parser.add_argument("-C", "--fetch-chunk-size", default=5000, type=int, help="Maximum number of assets to fetch with a single API call")
parser.add_argument("-l", "--log-level", default="INFO", choices=['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'], help="Log level to use")
parser.add_argument("-k", "--insecure", action="store_true", help="Pass to ignore SSL verification")
parser.add_argument("-i", "--ignore", action="append",
                    help="""Use either literals or glob-like patterns to ignore assets for tag name creation.
                            This filter is evaluated after any values passed with --path-filter. May be specified multiple times.""")
parser.add_argument("-m", "--mode", default=SCRIPT_MODE_CREATE, choices=[SCRIPT_MODE_CREATE],
                    help="""Mode for the script to run with.
                            CREATE = Create tags based on folder names and provided arguments; 
                            """)
parser.add_argument("-f", "--path-filter", action="append",
                    help="""Use either literals or glob-like patterns to filter assets before tag name creation.
                            This filter is evaluated before any values passed with --ignore. May be specified multiple times.""")

parser.add_argument("--api-timeout",  default=REQUEST_TIMEOUT_DEFAULT, type=int, help="Timeout when requesting Immich API in seconds")


args = vars(parser.parse_args())
# set up logger to log in logfmt format
logging.basicConfig(level=args["log_level"], stream=sys.stdout, format='time=%(asctime)s level=%(levelname)s msg=%(message)s')
logging.Formatter.formatTime = (lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).astimezone().isoformat(sep="T",timespec="milliseconds"))

root_paths = args["root_path"]
base_tags = args["base_tag"]
root_url = args["api_url"]
api_key = determine_api_key(args["api_key"], args["api_key_type"])
if api_key is None:
    logging.fatal("Unable to determine API key with API Key type %s", args["api_key_type"])
    sys.exit(1)
number_of_images_per_request = args["chunk_size"]
number_of_assets_to_fetch_per_request = args["fetch_chunk_size"]
unattended = args["unattended"]
tag_levels = args["tag_levels"]
# tag Levels Range handling
tag_levels_range_arr = ()
tag_name_post_regex = args["tag_name_post_regex"]
insecure = args["insecure"]
ignore_tags = args["ignore"]
mode = args["mode"]

path_filter = args["path_filter"]
api_timeout = args["api_timeout"]


# Override unattended if we're running in destructive mode
if mode != SCRIPT_MODE_CREATE:
    # pylint: disable=C0103
    unattended = False

is_docker = os.environ.get(ENV_IS_DOCKER, False)

logging.debug("root_path = %s", root_paths)
logging.debug("base_tags = %s", base_tags)
logging.debug("root_url = %s", root_url)
logging.debug("api_key = %s", api_key)
logging.debug("number_of_images_per_request = %d", number_of_images_per_request)
logging.debug("number_of_assets_to_fetch_per_request = %d", number_of_assets_to_fetch_per_request)
logging.debug("unattended = %s", unattended)
logging.debug("tag_levels = %s", tag_levels)
#logging.debug("tag_levels_range = %s", tag_levels_range)
logging.debug("tag_name_post_regex= %s", tag_name_post_regex)
logging.debug("insecure = %s", insecure)
logging.debug("ignore = %s", ignore_tags)
logging.debug("mode = %s", mode)

logging.debug("path_filter = %s", path_filter)

logging.debug("api_timeout = %s", api_timeout)


# Verify tag levels
if is_integer(tag_levels) and tag_levels == 0:
    logging.info("Tag level cannot be 0!")
    parser.print_help()
    sys.exit(1)

# Verify base tag
if len(base_tags) > 1 and len(base_tags) != len(root_paths):
    logging.error("Number of base tags must be 1 or equal to the number of root paths")
    parser.print_help()
    sys.exit(1)



# Request arguments for API calls
requests_kwargs = {
    'headers' : {
        'x-api-key': api_key,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    },
    'verify' : not insecure
}

if insecure:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Verify tag levels range
if not is_integer(tag_levels):
    tag_levels_range_split = tag_levels.split(",")
    if any([
            len(tag_levels_range_split) != 2,
            not is_integer(tag_levels_range_split[0]),
            not is_integer(tag_levels_range_split[1]),
            int(tag_levels_range_split[0]) == 0,
            int(tag_levels_range_split[1]) == 0,
            (int(tag_levels_range_split[1]) < 0 >= int(tag_levels_range_split[0])),
            (int(tag_levels_range_split[0]) < 0 >= int(tag_levels_range_split[1])),
            (int(tag_levels_range_split[0]) < 0 and int(tag_levels_range_split[1]) < 0 and int(tag_levels_range_split[0]) > int(tag_levels_range_split[1]))
        ]):
        logging.error(("Invalid tag_levels range format! If a range should be set, the start level and end level must be separated by a comma like '<startLevel>,<endLevel>'. "
                      "If negative levels are used in a range, <startLevel> must be less than or equal to <endLevel>."))
        sys.exit(1)
    tag_levels_range_arr = tag_levels_range_split
    # Convert to int
    tag_levels_range_arr[0] = int(tag_levels_range_split[0])
    tag_levels_range_arr[1] = int(tag_levels_range_split[1])
    # Special case: both levels are negative and end level is -1, which is equivalent to just negative tag level of start level
    if(tag_levels_range_arr[0] < 0 and tag_levels_range_arr[1] == -1):
        tag_levels = tag_levels_range_arr[0]
        tag_levels_range_arr = ()
        logging.debug("tag_levels is a range with negative start level and end level of -1, converted to tag_levels = %d", tag_levels)
    else:
        logging.debug("valid tag_levels range argument supplied")
        logging.debug("tag_levels_start_level = %d", tag_levels_range_arr[0])
        logging.debug("tag_levels_end_level = %d", tag_levels_range_arr[1])
        # Deduct 1 from tag start levels, since tag levels start at 1 for user convenience, but arrays start at index 0
        if tag_levels_range_arr[0] > 0:
            tag_levels_range_arr[0] -= 1
            tag_levels_range_arr[1] -= 1

# Create ignore regular expressions
ignore_tags_regex = []
if ignore_tags:
    for ignore_tags_entry in ignore_tags:
        ignore_tags_regex.append(glob_to_re(expand_to_glob(ignore_tags_entry)))

# Create path filter regular expressions
path_filter_regex = []
if path_filter:
    for path_filter_entry in path_filter:
        path_filter_regex.append(glob_to_re(expand_to_glob(path_filter_entry)))

# append trailing slash to all root paths
# pylint: disable=C0200
for i in range(len(root_paths)):
    if root_paths[i][-1] != '/':
        root_paths[i] = root_paths[i] + '/'
# append trailing slash to root URL
if root_url[-1] != '/':
    root_url = root_url + '/'

version = fetch_server_version()
# Check version
if version['major'] == 1 and version ['minor'] < 106:
    logging.fatal("This script only works with Immich Server v1.106.0 and newer! Update Immich Server or use script version 0.8.1!")
    sys.exit(1)



logging.info("Requesting all assets")
assets = fetch_assets(False, True)
logging.info("%d photos found", len(assets))



logging.info("Sorting assets to corresponding tags using folder name")
tags_to_create = build_tag_list(assets, root_paths, base_tags)
tags_to_create = dict(sorted(tags_to_create.items(), key=lambda item: item[0]))

logging.info("%d tags identified", len(tags_to_create))
logging.info("tag list: %s", list(tags_to_create.keys()))

if not unattended and mode == SCRIPT_MODE_CREATE:
    if is_docker:
        print("Check that this is the list of tags you want to create. Run the container with environment variable UNATTENDED set to 1 to actually create these tags.")
        sys.exit(0)
    else:
        print("Press enter to create these tags, Ctrl+C to abort")
        input()

logging.info("Listing existing tags on immich")

tags = fetch_tags()
tag_to_id = {tag['value']:tag['id'] for tag in tags }
logging.info("%d existing tags identified", len(tags))

# mode CREATE
logging.info("Creating tags if needed")
created_tags = []
# List for gathering all asset UUIDs for later archiving
asset_uuids_added = []
for tag_to_create, tag_assets in tags_to_create.items():
    if not tag_to_create in tag_to_id:
        # Create tag
        tag_id = create_tag(tag_to_create)
        tag_to_id[tag_to_create] = tag_id
        created_tags.append(tag_to_create)
        logging.info('tag %s added!', tag_to_create)
    else:
        tag_id = tag_to_id[tag_to_create]

    logging.info("Adding assets to tag %s", tag_to_create)
    assets_added = add_assets_to_tag(tag_id, tag_assets)
    if len(assets_added) > 0:
        asset_uuids_added += assets_added
        logging.info("%d new assets added to %s", len(assets_added), tag_to_create)

logging.info("%d tags created", len(created_tags))
logging.info("Done!")
