import argparse
import zipfile
import xmltodict
import requests
import json
import hashlib
import sys
import io
import os
import pkg_resources
from pathlib import Path


org_id = None
_snyk_api_headers = None
snyk_api_base_url = 'https://snyk.io/api/v1/'


def parse_command_line_args(command_line_args):
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument('--orgId', type=str,
                        help='Optional: the Snyk Organisation Id. Will use user default org if not set.')

    parser.add_argument('jar_path', nargs='+', metavar='/path/to/package.jar', type=str,
                        help='Path to Java jar(s) to test or . for jars in current directory')

    parser.add_argument('--jsonOutput', type=str,
                        help='Optional: name or path of JSON file to save results to in JSON format.')

    args = parser.parse_args(command_line_args)

    if not args.jar_path:
        parser.error('You must specify jar(s) to test')

    return args


def get_token(token_file_path=None):
    home = str(Path.home())
    default_path = '%s/.config/configstore/snyk.json' % home

    path = token_file_path or default_path

    try:
        with open(path, 'r') as f:
            json_obj = json.load(f)
            token = json_obj['api']
            return token
    except:
        print('Snyk auth token not found at %s' % path)
        print('Run `snyk auth` (see https://github.com/snyk/snyk#installation) or manually create this file with your token.')
        quit()


def get_snyk_api_headers(token_file_path=None):
    global _snyk_api_headers

    if not _snyk_api_headers:
        snyk_token = get_token(token_file_path)

        _snyk_api_headers = {
            'Authorization': 'token %s' % snyk_token
        }

    return _snyk_api_headers


def snyk_test_java_package(package_group_id, package_artifact_id, package_version):
    print('Snyk test package %s:%s@%s...' % (package_group_id, package_artifact_id, package_version))

    if org_id:
        full_api_url = '%stest/maven/%s/%s/%s?org=%s' % (
            snyk_api_base_url, package_group_id, package_artifact_id, package_version, org_id)
    else:
        full_api_url = '%stest/maven/%s/%s/%s' % (
            snyk_api_base_url, package_group_id, package_artifact_id, package_version)

    # https://snyk.docs.apiary.io/#reference/test/maven/test-for-issues-in-a-public-package-by-group-id,-artifact-id-and-version

    snyk_api_headers = get_snyk_api_headers()
    resp = requests.get(full_api_url, headers=snyk_api_headers)
    json_res = resp.json()

    all_vulnerability_issues = json_res['issues']['vulnerabilities']
    all_license_issues = json_res['issues']['licenses']

    print('Security Vulnerabilities:')

    if len(all_vulnerability_issues) > 0:
        for v in all_vulnerability_issues:
            print(v['id'])
            print('  %s' % v['title'])
            print('  %s' % v['url'])
            print('  %s@%s' % (v['package'], v['version']))
            print('  identifiers: %s' % v['identifiers']['CVE'])
            print('  severity: %s' % v['severity'])
            print('  language: %s' % v['language'])
            print('  packageManager: %s' % v['packageManager'])
            print('  isUpgradable: %s' % v['isUpgradable'])
            print('  isPatchable: %s' % v['isPatchable'])
            print()
    else:
        print('  (none found)')

    print('License Issues:')
    if len(all_license_issues) > 0:
        for l in all_license_issues:
            print(l)
    else:
        print('  (none found)')

    high_vulns_list = [v for v in all_vulnerability_issues if v['severity'] == 'high']
    medium_vulns_list = [v for v in all_vulnerability_issues if v['severity'] == 'medium']
    low_vulns_list = [v for v in all_vulnerability_issues if v['severity'] == 'low']
    print('\nSummary:')
    print('%s vulnerabilities found:' % len(all_vulnerability_issues))
    print('  %s high severity' % len(high_vulns_list))
    print('  %s medium severity' % len(medium_vulns_list))
    print('  %s low severity' % len(low_vulns_list))

    high_license_list = [v for v in all_license_issues if v['severity'] == 'high']
    medium_license_list = [v for v in all_license_issues if v['severity'] == 'medium']
    low_license_list = [v for v in all_license_issues if v['severity'] == 'low']
    print('\n%s licenses found' % len(all_license_issues))
    print('  %s high severity' % len(high_license_list))
    print('  %s medium severity' % len(medium_license_list))
    print('  %s low severity' % len(low_license_list))

    print()

    return json_res['issues']


def compute_file_sha1(file_path):
    buffer_size = io.DEFAULT_BUFFER_SIZE
    sha1_hash = hashlib.sha1()

    with open(file_path, 'rb') as f:
        block = f.read(buffer_size)
        while len(block):
            sha1_hash.update(block)
            block = f.read(buffer_size)

    hash_str = sha1_hash.hexdigest()

    return hash_str


def get_package_info_by_jar_filename(jar_path):
    all_package_results = []

    split_on_slash = jar_path.split('/')
    if len(split_on_slash) > 0:
        # jar_path = split_on_slash[len(split_on_slash - 1)]
        jar_path = split_on_slash[-1]  # [-1] yields the last item in the list
        print(jar_path)

    last_index_of_dash = jar_path.rfind('-')

    if last_index_of_dash == -1:
        print('warning - found file without version (%s) - bailing\n' % jar_path)
        return

    a = jar_path[0:last_index_of_dash]
    v = jar_path[last_index_of_dash + 1:]
    v = v.strip('.jar')

    maven_api_url = 'https://search.maven.org/solrsearch/select?q=a:"%s" AND v:"%s"&wt=json' % (a, v)

    resp = requests.get(maven_api_url)
    json_resp = resp.json()
    # print(json_resp)

    for d in json_resp['response']['docs']:
        full_id = d['id']
        group_id = d['g']
        artifact_id = d['a']
        version = d['v']

        package_info = {
            'fullId': full_id,
            'groupId': group_id,
            'artifactId': artifact_id,
            'version': version
        }

        all_package_results.append(package_info)

    return all_package_results


def get_package_info_by_jar_file_hash(jar_path):
    jar_file_stats = os.stat(jar_path)
    if jar_file_stats.st_size == 0:
        print('warning: JAR file size is 0')
        return []

    jar_hash_str = compute_file_sha1(jar_path)
    maven_api_url = 'https://search.maven.org/solrsearch/select?q=1:"%s"' % jar_hash_str

    resp = requests.get(maven_api_url)
    json_resp = resp.json()

    all_package_results = []
    for d in json_resp['response']['docs']:
        full_id = d['id']
        group_id = d['g']
        artifact_id = d['a']
        version = d['v']

        package_info = {
            'fullId': full_id,
            'groupId': group_id,
            'artifactId': artifact_id,
            'version': version
        }

        all_package_results.append(package_info)

    return all_package_results


def get_package_info_by_analyzing_jar_contents(jar_path):
    all_package_results = []
    try:
        with zipfile.ZipFile(jar_path) as jar_as_zipfile:
            for f in jar_as_zipfile.filelist:
                rel_path = f.filename

                if rel_path.endswith('pom.xml'):
                    try:
                        print(rel_path)
                        with jar_as_zipfile.open(rel_path, 'r') as jar_manifest_file:
                            pom_contents = jar_manifest_file.read()
                            x = pom_contents.decode('utf-8')
                            doc = xmltodict.parse(x)
                            group_id = doc['project']['groupId']
                            artifact_id = doc['project']['artifactId']
                            version = doc['project']['version']

                            print('Found pom.xml with %s:%s@%s' % (group_id, artifact_id, version))

                            package_info = {
                                'fullId': '%s:%s:%s' % (group_id, artifact_id, version),
                                'groupId': group_id,
                                'artifactId': artifact_id,
                                'version': version
                            }

                            all_package_results.append(package_info)
                    except KeyError as ke:
                        print('Warning - detected pom does not contain groupId/artifactId/version')

    except zipfile.BadZipFile as e:
        print('Could not unzip JAR file: %s' % jar_path)

    return all_package_results


def analyze_jar(jar_path):
    print('Identifying package for %s' % jar_path)

    matching_packages_from_hash_lookup = []
    matching_packages_from_hash_lookup = get_package_info_by_jar_file_hash(jar_path)

    # Analyze by searching for pom.xml files in the JAR which identify the package
    matching_packages_from_jar_contents = []
    if not matching_packages_from_hash_lookup:
        matching_packages_from_jar_contents = get_package_info_by_analyzing_jar_contents(jar_path)

    matching_packages_from_filename_lookup = []
    if not matching_packages_from_hash_lookup:
        # Analyze by trying to resolve the package by JAR filename - the least reliable way to ID a jar
        matching_packages_from_filename_lookup = get_package_info_by_jar_filename(jar_path)

    results = []
    packages_to_test = []

    if len(matching_packages_from_hash_lookup) > 0:
        packages_to_test = matching_packages_from_hash_lookup

    elif len(matching_packages_from_jar_contents) > 0:
        # test the packages identified by pom.xml files in the JAR
        packages_to_test = matching_packages_from_jar_contents

    elif len(matching_packages_from_filename_lookup) > 0:
        # no pom.xml found - have to rely on Maven lookup
        # there may be more than one package with the matching artifact/version
        packages_to_test = matching_packages_from_filename_lookup

    else:
        # no package identified
        print('No package identified for %s' % jar_path)

    for p in packages_to_test:
        issues = snyk_test_java_package(p['groupId'], p['artifactId'], p['version'])
        new_res = {
            'fullId': p['fullId'],
            'groupId': p['groupId'],
            'artifactId': p['artifactId'],
            'version:': p['version'],
            'vulnerabilities': issues['vulnerabilities'],
            'license-issues': issues['licenses']
        }
        results.append(new_res)

    return results


def get_list_of_jars_in_directory(directory_path):
    jars_list = []
    dir_listing = pkg_resources.safe_listdir(directory_path)

    for item in dir_listing:
        if item.endswith('.jar'):
            full_path = '%s/%s' % (directory_path, item)
            jars_list.append(full_path)

    return jars_list


if __name__ == '__main__':
    args = parse_command_line_args(sys.argv[1:])
    if args.orgId:
        org_id = args.orgId

    jars_to_test = []

    if len(args.jar_path) == 1:
        single_input_arg = args.jar_path[0]

        # could be a jar or a directory or '.' or something a single jar, or something else (invalid)
        if args.jar_path[0] == '.':
            current_directory = os.getcwd()
            test_dir = current_directory
            jars_to_test = get_list_of_jars_in_directory(test_dir)
            if not jars_to_test:
                print('Directory contains no jars: . (%s)' % test_dir)

        elif os.path.isdir(args.jar_path[0]):
            test_dir = args.jar_path[0]
            jars_to_test = get_list_of_jars_in_directory(test_dir)
            if not jars_to_test:
                print('Directory contains no jars: %s' % test_dir)

        elif single_input_arg.endswith('jar'):
            jars_to_test.append(single_input_arg)

        else:
            print('Invalid single input')
    else:
        jars_to_test = args.jar_path

    if jars_to_test:
        all_results = []
        for j in jars_to_test:
            print('Analyzing jar %s...' % j)
            jar_results = analyze_jar(j)

            obj = {
                'jar': j,
                'matching-packages': jar_results
            }
            all_results.append(obj)
            print()

        if args.jsonOutput:
            with open(args.jsonOutput, 'w') as output_json_file:
                print(json.dump(all_results, output_json_file, indent=2))

    print('\ndone')
