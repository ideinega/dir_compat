#!/usr/bin/env python3

import argparse
import os
import sys
from typing import Dict, List, Tuple, Set

FS_NTFS = 'ntfs'
FS_EXFAT = 'exfat'
FS_EXT = 'ext4'
FS_EXT_ENCRYPTED = 'ecryptfs'
FILESYSTEMS_SUPPORTED = FS_NTFS, FS_EXFAT, FS_EXT, FS_EXT_ENCRYPTED

EXT_PROHIBITED_SYMBOLS = {'/'}
WIN_PROHIBITED_SYMBOLS = {'/', '\\', ':', '*', '?', '"', '<', '>', '|'}
WIN_PROHIBITED_NAMES = ('CON', 'PRN', 'AUX', 'CLOCK$', 'NUL',
                        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
                        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9')

WIN_FILENAME_LENGTH_LIMIT_SYMBOLS = 255
EXT_FILENAME_LENGTH_LIMIT_BYTES = 255
EXT_ENCRYPTED_FILENAME_LENGTH_LIMIT_BYTES = 143

EXFAT_FULL_PATH_LIMIT_SYMBOLS = 32760
NTFS_FULL_PATH_LIMIT_SYMBOLS = 32767
EXT_ENCRYPTED_FULL_PATH_LIMIT_SYMBOLS = 4095


def _get_vars_from_kwargs(**kwargs) -> Tuple[str]:
    filename = kwargs['filename']
    path = kwargs['path']
    full_path = os.path.sep.join([path, filename])
    filesystems = ', '.join(kwargs['fs'])
    siblings = kwargs['siblings']
    return filename, full_path, filesystems, siblings


def _filename_limit(encode: bool, limit: int, **kwargs) -> str | None:
    filename, full_path, fs, _ = _get_vars_from_kwargs(**kwargs)
    units = 'symbols'
    if encode:
        filename = filename.encode()
        units = 'bytes'
    if len(filename) > limit:
        return f"{full_path} filename is more than {limit} {units}, which isn't allowed on {fs}"


def _ext_filename_limit(**kwargs) -> str | None:
    return _filename_limit(True, EXT_FILENAME_LENGTH_LIMIT_BYTES, **kwargs)


def _ext_encrypted_filename_limit(**kwargs) -> str | None:
    return _filename_limit(True, EXT_ENCRYPTED_FILENAME_LENGTH_LIMIT_BYTES, **kwargs)


def _windows_filename_limit(**kwargs) -> str | None:
    return _filename_limit(False, WIN_FILENAME_LENGTH_LIMIT_SYMBOLS, **kwargs)


def _path_length_limit(encode: bool, limit: int, **kwargs) -> str | None:
    _, full_path, fs, _ = _get_vars_from_kwargs(**kwargs)
    units = 'symbols'
    if encode:
        full_path = full_path.encode()
        units = 'bytes'
    if len(full_path) > limit:
        return f"{full_path} path length is than {limit} {units}, which isn't allowed on {fs}"


def _ext_encrypted_path_length_limit(**kwargs) -> str | None:
    return _path_length_limit(True, EXT_ENCRYPTED_FULL_PATH_LIMIT_SYMBOLS, **kwargs)


def _ntfs_path_length_limit(**kwargs) -> str | None:
    return _path_length_limit(False, NTFS_FULL_PATH_LIMIT_SYMBOLS, **kwargs)


def _exfat_path_length_limit(**kwargs) -> str | None:
    return _path_length_limit(False, EXFAT_FULL_PATH_LIMIT_SYMBOLS, **kwargs)


def _symbols_not_allowed(prohibited_set: Set[str], **kwargs) -> str | None:
    filename, full_path, fs, _ = _get_vars_from_kwargs(**kwargs)
    prohibited = set(filename) & prohibited_set
    if prohibited:
        return f"{full_path} contains \"{''.join(prohibited)}\", which isn't allowed on {fs}"


def _win_symbols_not_allowed(**kwargs) -> str | None:
    return _symbols_not_allowed(WIN_PROHIBITED_SYMBOLS, **kwargs)


def _ext_symbols_not_allowed(**kwargs) -> str | None:
    return _symbols_not_allowed(EXT_PROHIBITED_SYMBOLS, **kwargs)


def _win_names_not_allowed(**kwargs) -> str | None:
    filename, full_path, fs, _ = _get_vars_from_kwargs(**kwargs)
    if filename.upper() in WIN_PROHIBITED_NAMES:
        return f"{full_path} is a reserved name on {fs}"


def _case_insensitive(**kwargs) -> str | None:
    filename, full_path, fs, siblings = _get_vars_from_kwargs(**kwargs)
    if filename.lower() in map(lambda x: x.lower(), siblings):
        return f"{full_path} has case-insensitive duplicate filenames in the same directory, which isn't allowed on {fs}"


NTFS_AND_EXFAT_COMMON_RULE_FUNCTIONS = [_case_insensitive, _win_names_not_allowed,
                                        _win_symbols_not_allowed, _windows_filename_limit]

RULE_FUNCTIONS = {
    FS_NTFS: NTFS_AND_EXFAT_COMMON_RULE_FUNCTIONS + [_ntfs_path_length_limit],
    FS_EXFAT: NTFS_AND_EXFAT_COMMON_RULE_FUNCTIONS + [_exfat_path_length_limit],
    FS_EXT: [_ext_symbols_not_allowed, _ext_filename_limit],
    FS_EXT_ENCRYPTED: [_ext_symbols_not_allowed, _ext_encrypted_filename_limit, _ext_encrypted_path_length_limit]
}


def get_rules(filesystems: Tuple[Dict]):
    rules = {}
    for filesystem in filesystems:
        for rule_function in RULE_FUNCTIONS[filesystem]:
            if rule_function in rules:
                rules[rule_function]['fs'].append(filesystem)
            else:
                rules[rule_function] = {'fun': rule_function, 'fs': [filesystem]}
    return list(rules.values())


def print_issues(issues: List[str], dir_count: int, file_count: int, directory: str, filesystems: Tuple[str]):
    print(f"Results of checking {directory} for compatibility issues with {', '.join(filesystems)}:")
    print(f"Checked {dir_count} directories and {file_count} files.")
    for issue in issues:
        print(issue)
    if not issues:
        print('No issues found.')


def check_file_or_subdir(path: str, filename: str, siblings: List[str], rules: List[Dict]) -> List[str]:
    issues = []
    if os.path.islink(os.path.sep.join([path, filename])):
        return issues
    for rule in rules:
        rule_issues = rule['fun'](path=path, filename=filename, siblings=siblings, fs=rule['fs'])
        if rule_issues:
            issues.append(rule_issues)
    return issues


def check_directory_recursively(base_path: str, dirname: str, rules: List[Dict]) -> Tuple[List[str], int, int]:
    # os.walk excludes . and ..
    issues = check_file_or_subdir(path=base_path, filename=dirname, siblings=[], rules=rules)
    dir_count = 0
    file_count = 0
    for current_path, dirs, files in os.walk(os.path.sep.join([base_path, dirname])):
        dir_count += len(dirs)
        file_count += len(files)
        files_and_dirs = dirs + files
        for file in files_and_dirs:
            siblings = [file_or_dir for file_or_dir in files_and_dirs if file_or_dir != file]
            file_issues = check_file_or_subdir(path=current_path, filename=file, siblings=siblings, rules=rules)
            if file_issues:
                issues.extend(file_issues)
    return issues, dir_count, file_count


def main() -> int:
    parser = argparse.ArgumentParser(prog='dir_compat',
                                     description='Directory compatibility checker, ignores symbolic links and files inaccessible due to permissions')
    parser.add_argument('-d', '--directory', help='Directory to check for compatibility', required=True)
    parser.add_argument('-f', '--filesystems', help='Filesystems to check compatibility with', choices=FILESYSTEMS_SUPPORTED,
                        default=FILESYSTEMS_SUPPORTED, nargs="+")
    args = parser.parse_args()
    directory = args.directory
    filesystems = args.filesystems
    if not (os.path.exists(directory) and os.path.isdir(directory)):
        print(f"{directory} isn't a directory")
        return 1
    rules = get_rules(filesystems=filesystems)
    path, dirname = os.path.split(directory)
    issues, dir_count, file_count = check_directory_recursively(base_path=path, dirname=dirname, rules=rules)
    print_issues(issues=issues, dir_count=dir_count, file_count=file_count, directory=directory, filesystems=filesystems)
    return 0


if __name__ == "__main__":
    sys.exit(main())
