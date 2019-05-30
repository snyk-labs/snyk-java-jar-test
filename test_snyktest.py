import snykjar


def test_arg_parsing_works_for_single_dot():
    cl_args = ['.']
    args = snykjar.parse_command_line_args(cl_args)
    assert len(args.jar_path) == 1
    assert args.jar_path[0] == '.'


def test_arg_parsing_works_for_single_directory():
    cl_args = ['/Users/foo/some/directory']
    args = snykjar.parse_command_line_args(cl_args)
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


def test_arg_parsing_handles_multiple_jars():
    cl_args = ['somejar1.jar', 'somejar2.jar', 'somejar3.jar']
    args = snykjar.parse_command_line_args(cl_args)
    assert len(args.jar_path) == 3
    assert args.jar_path[0] == cl_args[0]
    assert args.jar_path[1] == cl_args[1]
    assert args.jar_path[2] == cl_args[2]

