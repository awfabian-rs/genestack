#!/bin/bash

if [[ "$LOG_LEVEL" == "DEBUG" ]]
then
    set -x
fi

log_level() {
    local LEVEL="$1"
    case "$LEVEL" in
      DEBUG)
        echo 5
        ;;
      INFO)
        echo 4
        ;;
      WARNING)
        echo 3
        ;;
      ERROR)
        echo 2
        ;;
      CRITICAL)
        echo 1
        ;;
      *)
        exit 3
        ;;
    esac
}

log_line() {
    local LEVEL
    LEVEL="$(log_level "$1")"
    if [[ "$LEVEL" -le "$(log_level "$LOG_LEVEL")" ]]
    then
        local line
        line=$(date +"%b %d %H:%M:%S $*")
        echo "$line" | tee -a "$LOG_FILE"
    fi
}

# Stats files init. These mostly get used to send to Prometheus, but you could
# just read them if you want to.

STATS_DIR="{$BACKUP_DIR}/stats"

[[ -d "$STATS_DIR" ]] || mkdir "$STATS_DIR"

metrics=("run_count" "save_to_disk_success_count" "save_to_disk_failure_count"
"upload_attempt_count" "upload_success_count" "upload_failure_count"
"disk_files_gauge" "swift_objects_gauge")

for metric_filename in "${metrics[@]}"
do
    metric_file_fullname="${STATS_DIR}/$metric_filename"
    [[ -e "$metric_file_fullname" ]] || echo "0" > "$metric_file_fullname"
done

# end stats file init

# Function to increment a stats counter $1
increment() {
    local STAT_NAME
    STAT_NAME="$1"
    STAT_FULL_FILENAME="${STATS_DIR}/$STAT_NAME"
    VALUE="$(cat $STAT_FULL_FILENAME)"
    ((VALUE++))
    echo "$VALUE" > $STAT_FULL_FILENAME
}

increment run_count

# Delete old backup files on volume.
cd "$BACKUP_DIR" || exit 2
[[ -e "$BACKUP_DIR/last_upload" ]] || touch "$BACKUP_DIR/last_upload" || exit 3
find "$BACKUP_DIR" -ctime +"$RETENTION_DAYS" -delete;

# Make a backup in YYYY/MM/DD directory in $BACKUP_DIR
YMD="$(date +"%Y/%m/%d")"
# kubectl-ko creates backups in $PWD, so we cd first.
mkdir -p "$YMD" && cd "$YMD" || exit 2
FAILED=false

if ! /kube-ovn/kubectl-ko nb backup
then
    log_line ERROR "nb backup failed"
    FAILED=true
fi
if ! /kube-ovn/kubectl-ko sb backup
then
    log_line ERROR "sb backup failed"
    FAILED=true
fi
if [[ "$FAILED" == "true" ]]
then
    increment save_to_disk_failure_count
else
    increment save_to_disk_success_count
fi

if [[ "$SWIFT_TEMPAUTH_UPLOAD" != "true" ]]
then
    exit 0
fi

# Everything from here forward deals with uploading to a Swift with tempauth.

cd "$BACKUP_DIR" || exit 2

increment upload_attempt_count

# Make a working "swift" command
SWIFT="kubectl -n openstack exec -i openstack-admin-client --
env -i ST_AUTH=$ST_AUTH ST_USER=$ST_USER ST_KEY=$ST_KEY
/var/lib/openstack/bin/swift"
export SWIFT

# Create the container if it doesn't exist
if ! $SWIFT stat "$CONTAINER" > /dev/null
then
  $SWIFT post "$CONTAINER"
fi

# upload_file uploads $1 to the container
upload_file() {
    FILE="$1"
    # Using OBJECT_NAME instead of FILE every time doesn't change the behavior,
    # but stops shellcheck from identifying this as trying to read and write
    # the same file.
    OBJECT_NAME="$FILE"
    if $SWIFT upload "$CONTAINER" --object-name "$OBJECT_NAME" - < "$FILE"
    then
      log_line INFO "SUCCESSFUL UPLOAD $FILE as object $OBJECT_NAME"
    else
      log_line ERROR "FAILURE API swift exited $? uploading $FILE as $OBJECT_NAME"
      FAILED_UPLOAD=true
    fi
}
export -f upload_file

# find created backups and upload them
cd "$BACKUP_DIR" || exit 2

FAILED_UPLOAD=false
find "$YMD" -type f -newer "$BACKUP_DIR/last_upload" | \
while read file
do
    upload_file "$file"
done

if [[ "$FAILED_UPLOAD" == "true" ]]
then
    increment upload_failure_count
else
    increment upload_success_count
fi

touch "$BACKUP_DIR/last_upload"
