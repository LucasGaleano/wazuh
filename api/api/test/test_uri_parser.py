from unittest.mock import MagicMock, patch

import pytest

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        from api.uri_parser import APIUriParser

PATH_PARAMS_DICT = {'param_key': 'param_value'}
FORM_DICT = {'form_key': 'form_value'}


@patch('api.uri_parser.APIUriParser.resolve_query')
@patch('api.uri_parser.APIUriParser.resolve_path')
@patch('api.uri_parser.APIUriParser.resolve_form')
@patch('api.uri_parser.APIError')
@patch('api.uri_parser.raise_if_exc')
@pytest.mark.parametrize('mock_parse_return', [';', 'mock_parse_return_value'])
@pytest.mark.parametrize('mock_q', [True, False])
def test_uri_parser(mock_exc, mock_aerror, mock_rform, mock_rpath, mock_rquery, mock_parse_return, mock_q):
    with patch('api.uri_parser.parse_api_param', return_value=mock_parse_return) as mock_parse:
        QUERY_DICT = {'q': 'q_value', 'status': 'StAtUs_Value'} if mock_q else {'status': 'StAtUs_ValuE'}

        uri_parser = APIUriParser({}, {})

        function = MagicMock()
        request = MagicMock()
        request.query = QUERY_DICT
        request.path_params = PATH_PARAMS_DICT
        request.form = FORM_DICT

        result = uri_parser(function)(request)
        if mock_q:
            mock_parse.assert_called_once_with(request.url, 'q')
            if mock_parse_return == ';':
                mock_exc.assert_called_once_with(mock_aerror.return_value)
                mock_aerror.assert_called_once_with(code=2009)
            mock_rquery.assert_called_once_with({'q': 'q_value', 'status': 'status_value'})
        else:
            mock_rquery.assert_called_once_with({'status': 'status_value'})
        mock_rpath.assert_called_once_with(PATH_PARAMS_DICT)
        mock_rform.assert_called_once_with(FORM_DICT)
        assert result == function.return_value
        function.assert_called_once_with(request)
