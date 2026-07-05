#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from functools import cached_property
from typing import Dict, Callable, List, Tuple, Set


NTFS = 'ntfs'
EXFAT = 'exfat'
EXT = 'ext4'
EXT_ENCRYPTED = 'ecryptfs'

FILESYSTEMS_SUPPORTED = [NTFS, EXFAT, EXT, EXT_ENCRYPTED]

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


@dataclass(frozen=True)
class FileContext:
    path: str
    filename: str
    siblings: List[str]

    @cached_property
    def full_path(self) -> str:
        return os.path.sep.join([self.path, self.filename])


def check_length_limit(context: FileContext, limit: int, filesystems: str, encode: bool = True, check_path: bool = True) -> str | None:
    filename_or_path = context.full_path if check_path else context.filename
    if encode:
        target = filename_or_path.encode()
        units = 'bytes'
    else:
        target = filename_or_path
        units = 'symbols'
    issue = None
    if len(target) > limit:
        issue = f"{filename_or_path} length is more than {limit} {units}, which isn't allowed on {filesystems}"
    return issue


def rule_ext_filename_limit(context: FileContext, filesystems: str) -> str | None:
    return check_length_limit(context=context, limit=EXT_FILENAME_LENGTH_LIMIT_BYTES, filesystems=filesystems, check_path=False)


def rule_ext_encrypted_filename_limit(context: FileContext, filesystems: str) -> str | None:
    return check_length_limit(context=context, limit=EXT_ENCRYPTED_FILENAME_LENGTH_LIMIT_BYTES, filesystems=filesystems, check_path=False)


def rule_win_filename_limit(context: FileContext, filesystems: str) -> str | None:
    return check_length_limit(context=context, limit=WIN_FILENAME_LENGTH_LIMIT_SYMBOLS, filesystems=filesystems, encode=False, check_path=False)


def rule_ext_encrypted_path_length_limit(context: FileContext, filesystems: str) -> str | None:
    return check_length_limit(context=context, limit=EXT_ENCRYPTED_FULL_PATH_LIMIT_SYMBOLS, filesystems=filesystems)


def rule_ntfs_path_length_limit(context: FileContext, filesystems: str) -> str | None:
    return check_length_limit(context=context, limit=NTFS_FULL_PATH_LIMIT_SYMBOLS, filesystems=filesystems, encode=False)


def rule_exfat_path_length_limit(context: FileContext, filesystems: str) -> str | None:
    return check_length_limit(context=context, limit=EXFAT_FULL_PATH_LIMIT_SYMBOLS, filesystems=filesystems, encode=False)


def rule_symbols_not_allowed(context: FileContext, prohibited_symbols: str, filesystems: Set[str]) -> str | None:
    issue = None
    prohibited_symbols_found = set(context.filename) & prohibited_symbols
    if prohibited_symbols_found:
        issue = f"{context.full_path} contains \"{''.join(prohibited_symbols_found)}\", which isn't allowed on {filesystems}"
    return issue


def rule_win_symbols_not_allowed(context: FileContext, filesystems: str) -> str | None:
    return rule_symbols_not_allowed(context=context, prohibited_symbols=WIN_PROHIBITED_SYMBOLS, filesystems=filesystems)


def rule_ext_symbols_not_allowed(context: FileContext, filesystems: str) -> str | None:
    return rule_symbols_not_allowed(context=context, prohibited_symbols=EXT_PROHIBITED_SYMBOLS, filesystems=filesystems)


def rule_win_names_not_allowed(context: FileContext, filesystems: str) -> str | None:
    issue = None
    if context.filename.upper() in WIN_PROHIBITED_NAMES:
        issue = f"{context.full_path} is a reserved name on {filesystems}"
    return issue


def rule_case_insensitive(context: FileContext, filesystems: str) -> str | None:
    issue = None
    if context.filename.lower() in map(lambda x: x.lower(), context.siblings):
        issue = f"{context.full_path} has case-insensitive duplicate filenames in the same directory, which isn't allowed on {filesystems}"
    return issue


class Rule:
    def __init__(self, function: Callable, filesystems_supported: Set[str]):
        self.function = function
        self.filesystems_supported = filesystems_supported
        self.filesystems_enabled: Set[str] | None = None

    @cached_property
    def filesystems_displayed(self) -> str:
        if self.filesystems_enabled is None:
            raise RuntimeError("Cannot access filesystems_displayed before rules have been enabled by get_rules_for_filesystems.")
        return ", ".join(self.filesystems_enabled)

    @staticmethod
    def get_rules_for_filesystems(rules: List[Rule], filesystems_enabled: Set[str]):
        for rule in rules:
            rule.filesystems_enabled = rule.filesystems_supported & filesystems_enabled

        return [rule for rule in rules if rule.filesystems_enabled]


NTFS_AND_EXFAT = {NTFS, EXFAT}

RULES = [
    Rule(function=rule_case_insensitive, filesystems_supported=NTFS_AND_EXFAT),
    Rule(function=rule_win_names_not_allowed, filesystems_supported=NTFS_AND_EXFAT),
    Rule(function=rule_win_symbols_not_allowed, filesystems_supported=NTFS_AND_EXFAT),
    Rule(function=rule_win_filename_limit, filesystems_supported=NTFS_AND_EXFAT),
    Rule(function=rule_ntfs_path_length_limit, filesystems_supported={NTFS}),
    Rule(function=rule_exfat_path_length_limit, filesystems_supported={EXFAT}),
    Rule(function=rule_ext_symbols_not_allowed ,filesystems_supported={EXT, EXT_ENCRYPTED}),
    Rule(function=rule_ext_filename_limit ,filesystems_supported={EXT}),
    Rule(function=rule_ext_encrypted_filename_limit ,filesystems_supported={EXT_ENCRYPTED}),
    Rule(function=rule_ext_encrypted_path_length_limit ,filesystems_supported={EXT_ENCRYPTED}),
]


def print_issues(issues: List[str], dir_count: int, file_count: int, directory: str, filesystems: List[str]):
    print(f"Results of checking {directory} for compatibility issues with {', '.join(filesystems)}:")
    print(f"Checked {dir_count} directories and {file_count} files.")
    for issue in issues:
        print(issue)
    if not issues:
        print('No issues found.')


def check_file_or_subdir(context: FileContext, rules: List[Rule]) -> List[str]:
    issues = []
    if os.path.islink(context.full_path):
        return issues
    for rule in rules:
        rule_issues = rule.function(context=context, filesystems=rule.filesystems_displayed)
        if rule_issues:
            issues.append(rule_issues)
    return issues


def check_directory_recursively(base_path: str, dirname: str, rules: List[Rule]) -> Tuple[List[str], int, int]:
    # os.walk excludes . and ..
    context = FileContext(path=base_path, filename=dirname, siblings=[])
    issues = check_file_or_subdir(context=context, rules=rules)
    dir_count = 0
    file_count = 0
    for current_path, dirs, files in os.walk(os.path.sep.join([base_path, dirname])):
        dir_count += len(dirs)
        file_count += len(files)
        files_and_dirs = dirs + files
        for file in files_and_dirs:
            siblings = [file_or_dir for file_or_dir in files_and_dirs if file_or_dir != file]
            context = FileContext(path=current_path, filename=file, siblings=siblings)
            file_issues = check_file_or_subdir(context=context, rules=rules)
            if file_issues:
                issues.extend(file_issues)
    return issues, dir_count, file_count


def main() -> int:
    parser = argparse.ArgumentParser(prog='dir_compat',
                                     description='Directory compatibility checker, ignores symbolic links and files inaccessible due to permissions')
    parser.add_argument('-d', '--directory', help='Directory to check for compatibility', required=True, metavar="DIR")
    parser.add_argument('-f', '--filesystems', help='One or more filesystems to check compatibility with (choices: %(choices)s, all of them if not specified)', choices=FILESYSTEMS_SUPPORTED,
                        default=FILESYSTEMS_SUPPORTED, nargs="*", metavar="FS")
    args = parser.parse_args()
    directory = args.directory
    filesystems = args.filesystems
    if not (os.path.exists(directory) and os.path.isdir(directory)):
        print(f"{directory} isn't a directory")
        return 1
    rules = Rule.get_rules_for_filesystems(rules=RULES, filesystems_enabled=set(filesystems))
    path, dirname = os.path.split(directory)
    issues, dir_count, file_count = check_directory_recursively(base_path=path, dirname=dirname, rules=rules)
    print_issues(issues=issues, dir_count=dir_count, file_count=file_count, directory=directory, filesystems=filesystems)
    return 0


if __name__ == "__main__":
    sys.exit(main())
