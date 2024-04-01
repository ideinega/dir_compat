#!/usr/bin/env python3

import unittest
from unittest.mock import patch  # , MagicMock
from io import StringIO
import os

from dir_compat import check_all


FILE_0_1_PROHIBITED = 'CLOCK$'
FILE_0_2_DUPLICATE = '.DIR_2'
FILE_0_3 = 'file_0_3'
FILE_0_4_PROHIBITED = 'file_0_4?'
SUBDIR_1 = 'dir_1'
FILE_1_1_PROHIBITED = '.file_1_1>'
FILE_1_2 = 'file_1_2'
FILE_1_3_PROHIBITED = 'file_1_3<'
SUBDIR_1_1 = 'dir_1_1'
FILE_1_1_1_PROHIBITED = 'file_1_1.'
SUBDIR_1_1_1 = 'dir_1_1_1'
FILE_1_1_1_1 = 'file_1_1_1_1'
FILE_1_1_1_2_PROHIBITED = 'file_1_1_1_2\\'
FILE_1_1_1_3_DUPLICATE = 'file_1_1_1_3a'
FILE_1_1_1_4_DUPLICATE = 'file_1_1_1_4A'
SUBDIR_2_DUPLICATE = '.dir_2'
FILE_2_1 = 'file_2_1'
FILE_2_2_PROHIBITED = 'file_2_2*'
SUBDIR_2_1_PROHIBITED = 'CON'


# TODO: add docstrings and annotations
class TestDirCompatLinToWin(unittest.TestCase):

    def create_file(self, path, filename, contents=''):
        with open(os.path.join(path, filename), 'w', encoding='utf-8') as f:
            f.write(contents)

    def create_subdir(self, *dirs):
        subdir_path = os.path.join(*dirs)
        os.makedirs(subdir_path)
        return subdir_path

    def setUp(self):
        self.test_dir = 'dir_compat_test_dir'
        os.makedirs(self.test_dir)
        self.create_file(self.test_dir, FILE_0_1_PROHIBITED)
        self.create_file(self.test_dir, FILE_0_2_DUPLICATE)
        self.create_file(self.test_dir, FILE_0_3)
        self.create_file(self.test_dir, FILE_0_4_PROHIBITED)
        dir_1 = self.create_subdir(self.test_dir, SUBDIR_1)

    def tearDown(self):
        os.rmdir(self.test_dir)

    @patch('sys.stdout', new_callable=StringIO)
    def assert_stdout(self, expected_output, mock_stdout):
        check_all(self.test_dir, ['ntfs'])
        self.assertEqual(mock_stdout.getvalue().strip(), expected_output.strip())

    def test_nonexistent_directory(self):
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            check_all('nonexistent_directory')
            self.assertIn('isn\'t a directory', mock_stdout.getvalue())

    def test_check_all_ntfs(self):
        expected_output = f"Results of checking {self.test_dir} for compatibility issues with ntfs:\n" \
                          f"Checked 0 directorires and 0 files.\n" \
                          "No issues found."
        self.assert_stdout(expected_output)

    def test_check_all_ext(self):
        return
        expected_output = f"Results of checking {self.test_dir} for compatibility issues with ext4:\n" \
                          f"Checked 0 directorires and 0 files.\n" \
                          "No issues found."
        self.assert_stdout(expected_output)

    def test_check_all_with_issues(self):
        return
        # Create a file with a prohibited symbol
        with open(os.path.join(self.test_dir, 'file/with/symbol.txt'), 'w') as file:
            file.write('test')

        expected_output = f"Results of checking {self.test_dir} for compatibility issues with ntfs:\n" \
                          f"{os.path.join(self.test_dir, 'file/with/symbol.txt')} contains \"/\", which isn't allowed on ntfs"
        self.assert_stdout(expected_output)


if __name__ == '__main__':
    unittest.main()
