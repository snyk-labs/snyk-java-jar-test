import snykjar
import tempfile
import json


def test_arg_parsing_works_for_single_dot():
    cl_args = ['.']
    args = snykjar.parse_command_line_args(cl_args)
    assert len(args.jar_path) == 1
    assert args.jar_path[0] == '.'

    cl_args = ['--orgId=123', '.']
    args = snykjar.parse_command_line_args(cl_args)
    assert args.orgId == '123'
    assert len(args.jar_path) == 1
    assert args.jar_path[0] == '.'


def test_arg_parsing_works_for_single_directory():
    cl_args = ['/Users/foo/some/directory']
    args = snykjar.parse_command_line_args(cl_args)
    assert len(args.jar_path) == 1
    assert args.jar_path[0] == '/Users/foo/some/directory'

    cl_args = ['--orgId=123', '/Users/foo/some/directory']
    args = snykjar.parse_command_line_args(cl_args)
    assert args.orgId == '123'
    assert len(args.jar_path) == 1
    assert args.jar_path[0] == '/Users/foo/some/directory'


def test_arg_parsing_works_for_single_jar():
    cl_args = ['somejar.jar']
    args = snykjar.parse_command_line_args(cl_args)
    assert len(args.jar_path) == 1
    assert args.jar_path[0] == 'somejar.jar'

    cl_args = ['./somejar.jar']
    args = snykjar.parse_command_line_args(cl_args)
    assert len(args.jar_path) == 1
    assert args.jar_path[0] == './somejar.jar'

    cl_args = ['/some/fully/qualified/path/somejar.jar']
    args = snykjar.parse_command_line_args(cl_args)
    assert len(args.jar_path) == 1
    assert args.jar_path[0] == '/some/fully/qualified/path/somejar.jar'

    # Now with --orgId
    cl_args = ['--orgId=123', 'somejar.jar']
    args = snykjar.parse_command_line_args(cl_args)
    assert args.orgId == '123'
    assert len(args.jar_path) == 1
    assert args.jar_path[0] == 'somejar.jar'

    cl_args = ['--orgId=123', './somejar.jar']
    args = snykjar.parse_command_line_args(cl_args)
    assert args.orgId == '123'
    assert len(args.jar_path) == 1
    assert args.jar_path[0] == './somejar.jar'

    cl_args = ['--orgId=123', '/some/fully/qualified/path/somejar.jar']
    args = snykjar.parse_command_line_args(cl_args)
    assert args.orgId == '123'
    assert len(args.jar_path) == 1
    assert args.jar_path[0] == '/some/fully/qualified/path/somejar.jar'


def test_arg_parsing_handles_multiple_jars():
    cl_args = ['somejar1.jar', 'somejar2.jar', 'somejar3.jar']
    args = snykjar.parse_command_line_args(cl_args)
    assert len(args.jar_path) == 3
    assert args.jar_path[0] == cl_args[0]
    assert args.jar_path[1] == cl_args[1]
    assert args.jar_path[2] == cl_args[2]

    # Now with --orgId
    cl_args = ['--orgId=123', 'somejar1.jar', 'somejar2.jar', 'somejar3.jar']
    args = snykjar.parse_command_line_args(cl_args)
    assert args.orgId == '123'
    assert len(args.jar_path) == 3
    assert args.jar_path[0] == 'somejar1.jar'
    assert args.jar_path[1] == 'somejar2.jar'
    assert args.jar_path[2] == 'somejar3.jar'


def test_can_read_token_from_snyk_api_config_file():
    obj_token_json = {
        'api': 'test-token'
    }

    with tempfile.NamedTemporaryFile() as temp_token_file:
        with open(temp_token_file.name, 'w') as temp_token_file_write:
            json.dump(obj_token_json, temp_token_file_write, indent=2)

        temp_filename = temp_token_file.name
        returned_token = snykjar.get_token(temp_filename)
        assert returned_token == 'test-token'


def test_can_get_snyk_api_headers_with_token_from_snyk_api_config_file():
    obj_token_json = {
        'api': 'test-token'
    }

    with tempfile.NamedTemporaryFile() as temp_token_file:
        with open(temp_token_file.name, 'w') as temp_token_file_write:
            json.dump(obj_token_json, temp_token_file_write, indent=2)

        temp_filename = temp_token_file.name

        returned_token = snykjar.get_token(temp_filename)
        assert returned_token == 'test-token'

        # TODO: It would be better to mock get_token than to add this filename optional parameter
        # to yet another function
        # something like when(snykjar.get_token(), return "test-token"

        snyk_headers_obj = snykjar.get_snyk_api_headers(temp_filename)

        assert snyk_headers_obj['Authorization'] == 'token %s' % 'test-token'

