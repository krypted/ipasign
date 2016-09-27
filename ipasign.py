#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import shutil
import zipfile
from subprocess import check_output
import plistlib

logger = logging.getLogger(__name__)


def get_args():
    """
    Parse command line arguments

    :return: command line arguments
    """

    parser = argparse.ArgumentParser(description='')

    parser.add_argument('ipa',
                        help='.ipa file path')

    parser.add_argument('--entitlements',
                        help='Entitlements .plist file path')

    parser.add_argument('--profile',
                        help='Provision profile file path')

    parser.add_argument('--identity',
                        help='Identity like "Krypted iPhone App"')

    parser.add_argument('--output',
                        default='resigned.ipa',
                        help='Resigned .ipa filename')

    parser.add_argument('--log',
                        help='Log file path')

    return parser.parse_args()


def setup_logger(log_level=logging.DEBUG, path=None):
    """
    Setup logger formats and handlers

    :param log_level: logging level
    :param path: log file path
    :return:
    """

    logger.setLevel(log_level)

    log_format = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
    log_format.datefmt = '%Y-%m-%d %H:%M:%S'

    log_stdout = logging.StreamHandler()
    log_stdout.setFormatter(log_format)
    log_stdout.setLevel(log_level)
    logger.addHandler(log_stdout)

    if path:
        log_file = logging.FileHandler(path)
        log_file.setFormatter(log_format)
        log_file.setLevel(log_level)
        logger.addHandler(log_file)


class Application(object):

    unzip_path = 'ipa'
    entitlements_path = 'Entitlements.plist'

    def __init__(self, ipa, *args, **kwargs):
        super(Application, self).__init__()

        self.ipa = ipa
        self.entitlements = kwargs.get('entitlements')
        self.profile = kwargs.get('profile')
        self.identity = kwargs.get('identity')
        self.output = kwargs.get('output')

        logger.info('Input parameters:\n'
                    'ipa: "{ipa}"\n'
                    'entitlements: "{entitlements}"\n'
                    'profile: "{profile}"\n'
                    'identity: "{identity}"'.format(ipa=self.ipa,
                                                    entitlements=self.entitlements,
                                                    profile=self.profile,
                                                    identity=self.identity))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if os.path.isdir(self.unzip_path):
            shutil.rmtree(self.unzip_path)

        if os.path.isfile(self.entitlements_path):
            os.remove(self.entitlements_path)

    def resign(self):
        # check if ipa file exist
        if not os.path.isfile(self.ipa):
            raise Exception('Ipa file ({}) does not exist'.format(self.ipa))

        # unzip ipa package
        with zipfile.ZipFile(self.ipa) as zfile:
            zfile.extractall(self.unzip_path)

        app_name = os.listdir('{}/Payload'.format(self.unzip_path))[0]

        # detect if provision profile exist in ipa package
        embedded_profile = '{}/Payload/{}/embedded.mobileprovision'.format(self.unzip_path, app_name)
        embedded_profile_exists = os.path.isfile(embedded_profile)
        if embedded_profile_exists:
            logger.info('Provision profile path in package: "{}"'.format(embedded_profile))

        # in case user specify new provision profile
        if self.profile:
            if os.path.isfile(self.profile):
                shutil.copyfile(self.profile, embedded_profile)
                logger.info('Copy "{}" to "{}"'.format(self.profile, embedded_profile))
            else:
                raise Exception('Profile file ({}) does not exist'.format(self.profile))
        else:
            if embedded_profile_exists:
                self.profile = embedded_profile
                logger.info('Use existing embedded.mobileprovision')
            else:
                raise Exception('Provision profile does not exist in ipa package')

        logger.info('Profile: "{}"'.format(self.profile))

        # parse provision profile
        provision_profile = check_output(['security', 'cms', '-D', '-i', self.profile])
        if not provision_profile:
            raise Exception('Fail to parse provision profile')
        else:
            logger.info('Provision profile content:\n{}'.format(provision_profile))
            provision_profile = plistlib.readPlistFromString(provision_profile)

        # generate entitlements.plist
        if not self.entitlements:
            entitlements = provision_profile.get('Entitlements')
            if not entitlements:
                raise Exception('No Entitlements in provision profile')

            plistlib.writePlist(entitlements, self.entitlements_path)
            self.entitlements = self.entitlements_path

        if not os.path.isfile(self.entitlements):
            raise Exception('No entitlement file ({})'.format(self.entitlements))
        else:
            entitlements = open(self.entitlements).read()
            logger.info('Entitlement content:\n{}'.format(entitlements))

        # read Info.plist
        info = plistlib.readPlist('{}/Payload/{}/Info.plist'.format(self.unzip_path, app_name))

        # get app id
        app_id = info.get('CFBundleIdentifier')
        if not app_id:
            raise Exception('CFBundleIdentifier does not exist in Info.plist')
        else:
            logger.info("application-identifier: {}".format(app_id))

        # modify app id
        # app_id = ''

        # check identity
        if not self.identity:
            team_name = provision_profile.get('TeamName')
            if not team_name:
                raise Exception('No TeamName in provision profile')

            self.identity = 'iPhone Distribution: {}'.format(team_name.encode('utf-8'))

        logger.info('Identity: {}'.format(self.identity))

        # get ResourceRules.plist
        resource_rules = '{}/Payload/{}/ResourceRules.plist'.format(self.unzip_path, app_name)

        # codesign the app
        codesign_args = ['codesign',
                         '--force',
                         '--sign', self.identity]

        if os.path.isfile(resource_rules):
            logger.info('ResourceRules.plist path: "{}"'.format(resource_rules))

            codesign_args.extend(['--resource-rules', resource_rules])
        else:
            logger.error('No ResourceRules.plist file. IGNORING!!!')

        codesign_args.extend(['--entitlements', self.entitlements,
                              '{}/Payload/{}'.format(self.unzip_path, app_name),
                              '--identifier', app_id])

        check_output(codesign_args)

        # zip the package
        with zipfile.ZipFile(self.output, mode='w', compression=zipfile.ZIP_DEFLATED) as zfile:
            for root, dirs, files in os.walk('{}'.format(self.unzip_path)):
                for f in files:
                    path = os.path.join(root, f)
                    zfile.write(path, arcname=path[len(self.unzip_path)+1:])


if __name__ == '__main__':

    args = get_args()

    setup_logger(path=args.log, log_level=logging.ERROR)

    with Application(args.ipa,
                     entitlements=args.entitlements,
                     profile=args.profile,
                     identity=args.identity,
                     output=args.output
                     ) as app:
        try:
            app.resign()
        except Exception as e:
            logger.error(e)
