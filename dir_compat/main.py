#!/usr/bin/env python3

import argparse
import os
from typing import List, Tuple, Set

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


NTFS_AND_EXFAT_COMMON_RESTRICTIONS = [_case_insensitive, _win_names_not_allowed,
                                      _win_symbols_not_allowed, _windows_filename_limit]

RESTRICTIONS = {
    FS_NTFS: NTFS_AND_EXFAT_COMMON_RESTRICTIONS + [_ntfs_path_length_limit],
    FS_EXFAT: NTFS_AND_EXFAT_COMMON_RESTRICTIONS + [_exfat_path_length_limit],
    FS_EXT: [_ext_symbols_not_allowed, _ext_filename_limit],
    FS_EXT_ENCRYPTED: [_ext_symbols_not_allowed, _ext_encrypted_filename_limit, _ext_encrypted_path_length_limit]
}


def check_all(directory: str, filesystems: List[str] = FILESYSTEMS_SUPPORTED) -> List[str]:
    def _get_checks():
        checks = {}
        for fs in filesystems:
            for check in RESTRICTIONS[fs]:
                if check.__name__ in checks:
                    checks[check.__name__]['fs'].append(fs)
                else:
                    checks[check.__name__] = {'fun': check, 'fs': [fs]}
        return list(checks.values())

    checks = _get_checks()

    def _check_file(path: str, filename: str, siblings: List[str]) -> List[str]:
        if os.path.islink(os.path.sep.join([path, filename])):
            return []

        results = []
        nonlocal checks
        for check in checks:
            check_result = check['fun'](path=path, filename=filename, siblings=siblings, fs=check['fs'])
            if check_result:
                results.append(check_result)
        return results

    def _walk_directory(current_path: str, dirname: str, siblings: List[str]) -> List[str]:
        results = _check_file(current_path, dirname, siblings)
        dir_count = 0
        file_count = 0
        for path, dirs, files in os.walk(os.path.sep.join([current_path, dirname])):
            dir_count += len(dirs)
            file_count += len(files)
            siblings = dirs + files
            for f in siblings:
                file_checks = _check_file(path, f, filter(lambda x: x != f, siblings))
                if file_checks:
                    results.extend(file_checks)
        return results, dir_count, file_count

    def print_results(results: List[str], dir_count: int, file_count: int):
        print(f"Results of checking {directory} for compatibility issues with {', '.join(filesystems)}:")
        print(f"Checked {dir_count} directorires and {file_count} files.")
        for result in results:
            print(result)
        if not results:
            print('No issues found.')

    if not (os.path.exists(directory) and os.path.isdir(directory)):
        print(f"{directory} isn't a directory")
        return 1

    path, dirname = os.path.split(directory)
    print_results(*_walk_directory(path, dirname, []))


def run():
    parser = argparse.ArgumentParser(prog='dir_compat',
                                     description='Directory compatibility checker, ignores symbolic links and files inaccessible due to permissions')
    parser.add_argument('-d', '--directory', help='Directory to check for compatibility', required=True)
    parser.add_argument('-f', '--filesystems', help='Filesystems to check compatibility with', choices=FILESYSTEMS_SUPPORTED,
                        default=FILESYSTEMS_SUPPORTED, nargs="+")
    args = vars(parser.parse_args())
    check_all(**args)


if __name__ == "__main__":
    run()
