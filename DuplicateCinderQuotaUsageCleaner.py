#!/usr/bin/env python

import MySQLdb
import argparse
import re
import sys
import logging
from datetime import datetime

# This script will clean up duplicated entries described in bug
# https://bugzilla.redhat.com/show_bug.cgi?id=1628236
# People running this script should read and understand what this
# script does, and bear the corresponding risk.
#
# High-level description
# This script will logon to mysql cinder database and
# 1) check quota_usages table and see if there is any duplicated
#    quota usage entries being inserted for a project corresponding
#    to specific resource type.
# 2) If duplicated entries were found in quota_usages table, it means
#    at certain time, duplicate quota record were made. Per Redhat
#    support, the row with more recent time on updated_at column should
#    be kept. The older row with less recent time on updated_at column
#    should be deleted as they are duplicated.
# 3) There could be corresponding reservation entries for above found
#    orphaned or outdated quota_usage entries, this script will also
#    locate those reservation entries and have them removed.
#

class DuplicateCinderQuotaUsageCleaner:
    def __init__(self, config, logger):
        self.logger = logger
        self.user, self.password, self.host, \
        self.port, self.db = self.get_mysql_credentials(config)

    def get_mysql_credentials(self, config_file):
        found = False
        with open(config_file) as f:
            for line in f:
                match = re.match('connection(.*)mysql://(.*):(.*)@(.*):(.*)/(.*)', line)
                if match:
                    user = match.group(2)
                    password = match.group(3)
                    host = match.group(4)
                    port = match.group(5)
                    db = match.group(6)
                    found = True
                    return user, password, host, port, db

        if found == False:
            self.logger.error('Cannot read mysql credential from {}'.format(config_file))
            sys.exit(1)

    def get_db_cursor(self, user, password, host, port, db):
        self.db_conn = MySQLdb.connect(host, user, password, db)
        cursor = self.db_conn.cursor()
        return cursor

    def get_duplicate_cinder_quota_entries(self):
        # this will list out all project that has duplicate cinder quota entires in quota_usages table
        # sorted by resource type. There should always be one single entry for each project and each
        # resource type. We will need to filter out which duplicate entries need to be deleted
        sql = "select count(resource), project_id, resource from quota_usages  group by project_id,resource having count(resource) > 1  order by count(resource)"
        self.cursor.execute(sql)
        rows = self.cursor.fetchall()
        if rows:
            self.logger.info('From {} duplicated project+resource combination fron cinder.quota_usages table'.format(len(rows)))
            for row in rows:
                count = row[0]
                project_id = row[1]
                resource = row[2]
                found_duplicate, id_to_keep, id_to_remove = self.find_quota_usages_to_delete(project_id, resource)
                if found_duplicate:
                    self.logger.info('project_id: {}, resource: {} usage_id_to_keep: {}, usage_id_to_remove: {}'.format(project_id, resource, id_to_keep, id_to_remove))
                    self.find_reservation_to_delete(project_id, id_to_remove)
                    if self.delete:
                        for id in id_to_remove:
                            sql = "delete from quota_usages where project_id = '{}' and resource = '{}' and id = {}".format(project_id, resource, id)
                            self.cursor.execute(sql)
                            self.db_conn.commit()
                            self.logger.info('Quota_usage id {} removed'.format(id))

    def find_quota_usages_to_delete(self, project_id, resource):
        sql = "select updated_at, id from quota_usages where project_id = '{}' and resource ='{}';".format(project_id, resource)
        self.cursor.execute(sql)
        rows = self.cursor.fetchall()
        found_duplicate = False
        id_to_keep = 0
        id_to_remove = []
        # if there is duplicate, num of rows will be greater than 1
        if len(rows) > 1:
            found_duplicate = True
            # have to find the row that contain latest update
            # the row has latest_update is the active row to be kept
            lastest_update = datetime.utcfromtimestamp(0)
            for row in rows:
                if row[0] > lastest_update:
                    latest_update = row[0]
                    id_to_keep = row[1]

            for row in rows:
                if row[1] != id_to_keep:
                    id_to_remove.append(int(row[1]))

        return found_duplicate, id_to_keep, id_to_remove

    def find_reservation_to_delete(self, project_id, usage_ids):
        for usage_id in usage_ids:
            sql = "select * from reservations where deleted_at is null and project_id = '{}' and usage_id = {}".format(project_id, usage_id)
            self.cursor.execute(sql)
            rows = self.cursor.fetchall()
            # column list
            # created_at, updated_at, deleted_at, deleted, id, uuid, usage_id, project_id, resource, delta, expire, allocated_id
            self.logger.info('Found {} stalled reservations under project_id: {} '.format(len(rows), project_id))
            self.logger.info('created_at, updated_at, deleted_at, deleted, id, uuid, usage_id, project_id, resource, delta, expire, allocated_id')
            for row in rows:
                created_at = row[0].strftime("%Y-%m-%d %H:%M:%S") if row[0] else None
                updated_at = row[1].strftime("%Y-%m-%d %H:%M:%S") if row[1] else None
                deleted_at = row[2].strftime("%Y-%m-%d %H:%M:%S") if row[2] else None
                expire = row[11].strftime("%Y-%m-%d %H:%M:%S") if row[11] else None
                line = '{}, {}, {}, {}, {}, {}, ' \
                       '{}, {}, {}, {}, {}, {}'.format(created_at, row[1], row[2], int(row[3]),
                                                       int(row[4]), row[5], int(row[6]), row[7],
                                                       row[8], row[9], row[10], expire)
                self.logger.info(line)
                if self.delete:
                    #sql = "delete from reservations where deleted_at is null and project_id = '{}' and usage_id = {} and id = ?".format(project_id, usage_id)
                    sql = "delete from reservations where deleted_at is null and project_id = '{}' and usage_id = {} and id = {}".format(project_id, usage_id, int(row[4]))
                    self.cursor.execute(sql)
                    self.db_conn.commit()
                    self.logger.info('Row id {} removed'.format(row[4]))

    def start(self, delete):
        self.delete = delete
        self.logger.info('Starting Duplicate quota_usage clean up tool, delete mode: {}'.format(delete))
        self.cursor = self.get_db_cursor(self.user, self.password,
                                         self.host, self.port, self.db)
        self.get_duplicate_cinder_quota_entries()
        self.cursor.close()

def parse_args():
    parser = argparse.ArgumentParser(
        description="Duplicate Cinder's quota_usage cleanup tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '--config', '-c', type=str, default='/etc/cinder/cinder.conf',
        help='Cinder configuration file path to read MySQL config from'
    )
    parser.add_argument(
        '--log', '-l', type=str, default='/var/log/duplicate_cinder_quota_usage_removal.log',
        help='Log file to store output'
    )
    parser.add_argument(
        '--delete-for-real', action='store_true',
        help='Proceed to delete the duplicate entries, default is false'
    )

    return parser.parse_args()

def get_logger(log_file, log_name):
    logger = logging.getLogger(log_name)
    logger.setLevel(logging.DEBUG)
    log_formatter = logging.Formatter(fmt='%(asctime)s - %(funcName)s - %(levelname)s: %(message)s')
    ch = logging.StreamHandler()
    ch.setFormatter(log_formatter)
    logger.addHandler(ch)
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(log_formatter)
        logger.addHandler(fh)

    return logger

def main():
    args = parse_args()
    logger = get_logger(args.log, "Cinder quota_usage cleanup")
    config_file = args.config
    cleaner = DuplicateCinderQuotaUsageCleaner(config=args.config,
                                               logger=logger)
    cleaner.start(args.delete_for_real)

main()
