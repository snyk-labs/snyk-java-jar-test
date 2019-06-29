import snykjar
import tempfile
import json
import pytest
import requests_mock
from mock import patch


def test_get_token_fails_if_token_file_not_found():
    with pytest.raises(FileNotFoundError) as pytest_wrapped_exception:
        t = snykjar.get_token('/some/path/that/does/not/exist/snyk.json')
    assert pytest_wrapped_exception.type == FileNotFoundError
    assert pytest_wrapped_exception.value.args[1] == 'No such file or directory'


def test_get_token_fails_if_token_file_cant_be_parsed():
    """Build a temp file with an invalid spec and make sure it fails"""

    obj_token_json = {
        'some-invalid-key': 'test-token'
    }

    with tempfile.NamedTemporaryFile() as temp_token_file:
        with open(temp_token_file.name, 'w') as temp_token_file_write:
            json.dump(obj_token_json, temp_token_file_write, indent=2)

        with pytest.raises(KeyError) as pytest_wrapped_exception:
            temp_filename = temp_token_file.name
            returned_token = snykjar.get_token(temp_filename)

        assert pytest_wrapped_exception.type == KeyError
        assert pytest_wrapped_exception.value.args[0] == 'api'


def test_get_token_works_with_well_formed_token_file():
    obj_token_json = {
        'api': 'test-token'
    }

    with tempfile.NamedTemporaryFile() as temp_token_file:
        with open(temp_token_file.name, 'w') as temp_token_file_write:
            json.dump(obj_token_json, temp_token_file_write, indent=2)

        temp_filename = temp_token_file.name
        returned_token = snykjar.get_token(temp_filename)
        assert returned_token == 'test-token'


def test_snyk_auth_header_is_correct():
    token = 'test-token'
    auth_headers = snykjar.get_snyk_api_headers(token)
    assert auth_headers['Authorization'] == 'token test-token'


def test_main_fails_if_token_file_does_not_exist():
    with patch('snykjar.get_default_token_path',
               return_value='/some/path/that/does/not/exist/snyk.json'):
        with pytest.raises(FileNotFoundError) as pytest_wrapped_exception:
            snykjar.main(['/path/to/jars'])
        assert pytest_wrapped_exception.type == FileNotFoundError


def test_main_fails_if_token_file_cant_be_parsed():
    """Build a temp file with an invalid spec and make the main fails properly"""

    obj_token_json = {
        'some-invalid-key': 'test-token'
    }

    with tempfile.NamedTemporaryFile() as temp_token_file:
        with open(temp_token_file.name, 'w') as temp_token_file_write:
            json.dump(obj_token_json, temp_token_file_write, indent=2)

        with patch('snykjar.get_default_token_path', return_value=temp_token_file.name):

            with pytest.raises(KeyError) as pytest_wrapped_exception:
                snykjar.main(['/path/to/jars'])

            assert pytest_wrapped_exception.type == KeyError
            assert pytest_wrapped_exception.value.args[0] == 'api'


def test_validate_token():
    with requests_mock.mock() as m:
        m.get('https://snyk.io/api/v1/',
              status_code=200,
              text='{"what orgs can the current token access?":"https://snyk.io/api/v1/orgs","what projects are owned by this org?":"https://snyk.io/api/v1/org/:id/projects","test a package for issues":"https://snyk.io/api/v1/test/:packageManager/:packageName/:packageVersion"}')
        is_valid = snykjar.validate_token('test-token')
        assert is_valid


def test_validate_token_fails_for_invalid_token():
    with requests_mock.mock() as m:
        m.get('https://snyk.io/api/v1/',
              status_code=401)
        is_valid = snykjar.validate_token('test-token')
        assert not is_valid


def test_main_fails_if_validate_token_fails():
    with patch('snykjar.get_token', return_value='test-token'):
        with patch('snykjar.validate_token', return_value=False):
            with pytest.raises(SystemExit) as pytest_wrapped_exception:
                snykjar.main(['/path/to/jars'])
            assert pytest_wrapped_exception.type == SystemExit
