#!/usr/bin/env sh

# parse comma separated root paths and wrap in quotes
oldIFS=$IFS
IFS=','
# disable globbing
set -f          
# parse ROOT_PATH CSV
main_root_path=""
additional_root_paths=""
for path in ${ROOT_PATH}; do
  if [ -z "$main_root_path" ]; then
    main_root_path="\"$path\""
  else
    additional_root_paths="--root-path \"$path\" $additional_root_paths"
  fi
done

base_tag_list=""
if [ ! -z "$BASE_TAG" ]; then
    for base_tag_entry in ${BASE_TAG}; do
        base_tag_list="--base-tag \"$base_tag_entry\" $base_tag_list"
    done
fi


IFS=$oldIFS

# parse semicolon separated root paths and wrap in quotes
oldIFS=$IFS
IFS=':'


# parse PATH_FILTER CSV
path_filter_list=""
if [ ! -z "$PATH_FILTER" ]; then
    for path_filter_entry in ${PATH_FILTER}; do
        path_filter_list="--path-filter \"$path_filter_entry\" $path_filter_list"
    done
fi

# parse IGNORE CSV
ignore_list=""
if [ ! -z "$IGNORE" ]; then
    for ignore_entry in ${IGNORE}; do
        ignore_list="--ignore \"$ignore_entry\" $ignore_list"
    done
fi

## parse ABLUM_NAME_POST_REGEX<n>
# Split on newline only
IFS=$(echo -en "\n\b")
tag_name_post_regex_list=""
# Support up to 10 regex patterns
regex_max=10
for regex_no in `seq 1 $regex_max`
do
    for entry in `env`
    do
        # check if env variable name begins with tag_POST_NAME_REGEX followed by a the current regex no and and equal sign
        pattern=$(echo "^tag_NAME_POST_REGEX${regex_no}+=.+")
        TEST=$(echo "${entry}" | grep -E "$pattern")
        if [ ! -z "${TEST}" ]; then
            value="${entry#*=}" # select everything after the first `=`
            tag_name_post_regex_list="$tag_name_post_regex_list --tag-name-post-regex $value"
        fi
    done
done

# reset IFS
IFS=$oldIFS

unattended=
if [ ! -z "$UNATTENDED" ]; then
    unattended="--unattended"
fi

api_key=""
api_key_type=""

if [ ! -z "$API_KEY" ]; then
    api_key=$API_KEY
    api_key_type="--api-key-type literal"
elif [ ! -z "$API_KEY_FILE" ]; then
    api_key=$API_KEY_FILE
    api_key_type="--api-key-type file"
fi

args="$api_key_type $unattended $main_root_path $API_URL $api_key"

if [ ! -z "$additional_root_paths" ]; then
    args="$additional_root_paths $args"
fi

if [ ! -z "$base_tag_list"]; then
    args="$base_tag_list $args"
fi

if [ ! -z "$tag_LEVELS" ]; then
    args="--tag-levels $tag_LEVELS $args"
fi

if [ ! -z "$tag_name_post_regex_list" ]; then
    args="$tag_name_post_regex_list $args"
fi

if [ ! -z "$FETCH_CHUNK_SIZE" ]; then
    args="--fetch-chunk-size $FETCH_CHUNK_SIZE $args"
fi

if [ ! -z "$CHUNK_SIZE" ]; then
    args="--chunk-size $CHUNK_SIZE $args"
fi

if [ ! -z "$LOG_LEVEL" ]; then
    args="--log-level $LOG_LEVEL $args"
fi

if [ "$INSECURE" = "true" ]; then
    args="--insecure $args"
fi

if [ ! -z "$ignore_list" ]; then
    args="$ignore_list $args"
fi

if [ ! -z "$MODE" ]; then
    args="--mode \"$MODE\" $args"
fi


if [ ! -z "$path_filter_list" ]; then
    args="$path_filter_list $args"
fi

if [ ! -z "$API_TIMEOUT" ]; then
    args="--api-timeout \"$API_TIMEOUT\" $args"
fi

BASEDIR=$(dirname "$0")
echo $args | xargs python3 -u $BASEDIR/immich_auto_tag.py
