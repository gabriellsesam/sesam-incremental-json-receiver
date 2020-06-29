from flask import Flask, request, abort, send_from_directory, Response
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
import requests
import datetime

import json
import logging
import os
import re
import sys
import urllib.parse
import logger as log
from dotty_dict import dotty

app = Flask(__name__)

SYSTEM = None
FULL_URL_PATTERN = None
UPDATED_URL_PATTERN = None
UPDATED_PROPERTY = None
OFFSET_BIGGER_AND_EQUAL = None
UPDATED_PROPERTY_FROM_FORMAT = None
UPDATED_PROPERTY_TO_FORMAT = None


def get_var(var):
    envvar = None
    envvar = os.getenv(var.upper())
    logger.debug("Setting %s = %s" % (var, envvar))
    return envvar


def error_handling():
    return '{} - {}, at line {}'.format(sys.exc_info()[0],
                                        sys.exc_info()[1],
                                        sys.exc_info()[2].tb_lineno)


class OpenUrlSystem():
    def __init__(self, config):
        self._config = config

    def make_session(self):
        session = requests.Session()
        session.headers = self._config['headers']
        return session


class Oauth2System():
    def __init__(self, config):
        """init AzureOauth2Client with a json config"""
        self._config = config
        self._get_token()

    def _get_token(self):
        """docstring for get_session"""
        # If no token has been created yet or if the previous token has expired, fetch a new access token
        # before returning the session to the callee
        if not hasattr(self, "_token") or self._token["expires_at"] < datetime.datetime.now().timestamp():
            oauth2_client = BackendApplicationClient(client_id=self._config["oauth2"]["client_id"])
            session = OAuth2Session(client=oauth2_client)
            logger.info("Updating token...")
            self._token = session.fetch_token(**self._config["oauth2"])

        logger.debug("ExpiresAt={}, now={}, diff={}".format(str(self._token.get("expires_at")),
                                                            str(datetime.datetime.now().timestamp()), str(
                self._token.get("expires_at", 0) - datetime.datetime.now().timestamp())))
        return self._token

    def make_session(self):
        token = self._get_token()
        client = BackendApplicationClient(client_id=self._config["oauth2"]["client_id"])
        session = OAuth2Session(client=client, token=token)
        if 'headers' in self._config:
            session.headers = self._config['headers']
        return session


# to remove favicon not found errormessages in the log
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


def generate_response_data(url, microservice_args, args_to_forward):
    is_first_yield = True
    is_limit_reached = False
    entity_count = 0
    limit = int(microservice_args.get('limit')) if microservice_args.get('limit') else None
    if microservice_args.get('ms_pagenum_param_at_src') and args_to_forward[
        microservice_args.get('ms_pagenum_param_at_src')]:
        pagenum = int(args_to_forward[microservice_args.get('ms_pagenum_param_at_src')])

    do_loop_request = microservice_args.get('do_loop_request')
    if do_loop_request:
        current_offset = 0
        pagesize_attribute = microservice_args.get('ms_loop_request_pagesize_attribute')
        total_count_attribute = microservice_args.get('ms_loop_request_total_attribute')
        offset_attribute = microservice_args.get('ms_loop_request_offset_attribute')
        offset_argument = microservice_args.get('ms_loop_request_offset_arg')
        all_page_count_offset_attributes = [offset_attribute, pagesize_attribute, total_count_attribute]

    yield '['
    try:
        with SYSTEM.make_session() as s:
            while True:
                if do_loop_request:
                    args_to_forward[offset_argument] = current_offset

                logger.debug('Getting from url={}, with params={}, with do_page={}'.format(url, args_to_forward,
                                                                                           microservice_args.get(
                                                                                               'do_page')))
                r = s.get(url, params=args_to_forward)
                if r.status_code not in [200, 204]:
                    logger.debug("Error {}:{}\n{}".format(r.status_code, r.text, r.content.decode('UTF-8')))
                    abort(r.status_code, r.text)

                rst = r.json() if r.status_code == 200 else []
                if type(rst) == dict:
                    rst = [rst]
                logger.debug('Got {} entities'.format(len(rst)))

                # read data from the data_property in the response json
                rst_data = []
                if microservice_args.get('data_property'):
                    for entity in rst:
                        rst_data.extend(entity[microservice_args.get('data_property')])
                else:
                    rst_data = rst

                split_response_into_children = microservice_args.get('ms_split_attribute_into_children')
                if split_response_into_children:
                    new_rst = []
                    if len(rst) != 0:
                        for response in rst:
                            if split_response_into_children in response:
                                if type(response[split_response_into_children]) == list:
                                    if len(response[split_response_into_children]) != 0:
                                        new_rst += response[split_response_into_children]
                                    else:
                                        logger.error(
                                            f'Cannot split entities from field "{split_response_into_children}" because it is empty!')
                                else:
                                    logger.error(
                                        f'Cannot split entities from field "{split_response_into_children}" because it is not a list!')
                            else:
                                logger.error(
                                    f'Cannot find attribute "{split_response_into_children}" to split response on!')
                        rst_data = new_rst
                        logger.debug(
                            f'Got {len(rst_data)} entities after splitting attribute "{split_response_into_children}"')
                    else:
                        logger.warning('Response had 0 entities so returning empty list..')
                        rst_data = []
                # apply sorting by updated_property
                if microservice_args.get('ms_do_sort'):
                    def get_updated_property(myjson):
                        return myjson[microservice_args.get('ms_updated_property')]

                    rst_data.sort(key=get_updated_property, reverse=False)

                entity_count += len(rst_data)
                # apply limit'ing
                if limit:
                    limit = limit - len(rst_data)
                    if limit < 0:
                        rst_data = rst_data[0:limit]
                        is_limit_reached = True

                # sesamify and generate final response data
                entities_to_return = []
                if microservice_args.get('call_issued_time') or microservice_args.get('ms_updated_property'):
                    for data in rst_data:
                        try:
                            if microservice_args.get('call_issued_time'):
                                data["_updated"] = microservice_args.get('call_issued_time')
                            elif microservice_args.get('ms_updated_property'):
                                dotted_data = dotty(data)
                                data["_updated"] = dotted_data[microservice_args.get('ms_updated_property')]
                            entities_to_return.append(data)
                        except KeyError as ke:
                            logger.error(
                                f'Cannot find key "{microservice_args.get("ms_updated_property")}" inside response {json.dumps(data, indent=2)}')
                            raise ke
                else:
                    entities_to_return = rst_data

                for entity in entities_to_return:
                    if is_first_yield:
                        is_first_yield = False
                    else:
                        yield ','
                    yield json.dumps(entity)

                if do_loop_request and len(rst) > 0:
                    # Check that we have the fields in the response before getting them.
                    # If response is a list iterate and get biggest offset, smallest pagesize and biggest totalcount.
                    offsets = []
                    counts = []
                    pagesizes = []
                    for response in rst:
                        for attribute in all_page_count_offset_attributes:
                            if attribute not in response:
                                raise KeyError(f'Cannot find attribute "{attribute}" in response!')
                        offsets.append(response[offset_attribute])
                        counts.append(response[total_count_attribute])
                        pagesizes.append(response[pagesize_attribute])

                    current_offset = max(offsets)
                    total_count = max(counts)
                    pagesize = min(pagesizes)

                    # If the current offset (e.g 50) + pagesize  (the amount we got in the response e.g 25) is less than total count then go again with a bigger offset.
                    if current_offset + pagesize < total_count:
                        current_offset += pagesize
                    else:
                        break
                else:
                    if not microservice_args.get('do_page') or len(entities_to_return) == 0 or is_limit_reached:
                        break
                    else:
                        pagenum += 1
                        args_to_forward[microservice_args.get('ms_pagenum_param_at_src')] = pagenum
        yield ']'
    except Exception as err:
        logger.error(err)
        yield error_handling()


def parse_qs(request):
    microservice_args = {'since': None, 'limit': None,
                         'ms_updated_property': UPDATED_PROPERTY,
                         'ms_updated_property_from_format': UPDATED_PROPERTY_FROM_FORMAT, #Not really used to pass along
                         'ms_updated_property_to_format': UPDATED_PROPERTY_TO_FORMAT, #Not really used to pass along
                         'ms_offset_bigger_and_equal': OFFSET_BIGGER_AND_EQUAL,
                         'ms_do_sort': False,
                         'ms_data_property': None,
                         'ms_since_param_at_src': None,
                         'ms_limit_param_at_src': None,
                         'ms_pagenum_param_at_src': None,
                         'ms_use_currenttime_as_updated': False,
                         'do_loop_request': False,
                         'ms_loop_request_pagesize_attribute': None,
                         'ms_loop_request_total_attribute': None,
                         'ms_loop_request_offset_arg': None,
                         'ms_loop_request_offset_attribute': None,
                         'ms_split_attribute_into_children': None
                         }
    limit = request.args.get('limit')
    since = request.args.get('since')
    for arg in request.args:
        logger.info(f'{arg}: {request.args.get(arg)}')

    if since:
        url = UPDATED_URL_PATTERN.replace('__path__', request.path[1:])
        if UPDATED_PROPERTY_FROM_FORMAT:
            datetime_since = None
            try:
                datetime_since = datetime.datetime.strptime(since, UPDATED_PROPERTY_FROM_FORMAT)
            except ValueError as ve:
                logger.info(f'Got date value error, if date-format ends with %z then ill try again and add back the +: {ve}')
                if UPDATED_PROPERTY_FROM_FORMAT.endswith('%z'):
                    datetime_since = datetime.datetime.strptime(since[0:-6] + '+' + since[-5:], UPDATED_PROPERTY_FROM_FORMAT)
            if UPDATED_PROPERTY_TO_FORMAT:
                since = datetime_since.strftime(UPDATED_PROPERTY_TO_FORMAT)
            else:
                since = str(datetime_since)
        url = url.replace('__since__', since)
    else:
        url = FULL_URL_PATTERN.replace('__path__', request.path[1:])

    if limit:
        url = url.replace('__limit__', limit)

    parsed_url = urllib.parse.urlsplit(url)
    url = urllib.parse.urlunsplit((parsed_url[0], parsed_url[1], parsed_url[2], None, parsed_url[4]))
    url_args = urllib.parse.parse_qs(parsed_url[3])
    request_args = urllib.parse.parse_qs(request.query_string.decode('utf-8'))
    # collect microservice_args from url_args and request_args giving the latter higher precedence
    for arg in microservice_args.keys():
        value = url_args.get(arg, [None])[0]
        if isinstance(value, bool):
            value = (value.lower() == "true")
        microservice_args[arg] = value

    for arg in microservice_args.keys():
        value = request_args.get(arg, [None])[0]
        if isinstance(value, bool):
            value = (value.lower() == "true")
        if value:
            microservice_args[arg] = value

    # set call_issued_time to use as _updated value
    if microservice_args.get('ms_use_currenttime_as_updated'):
        microservice_args.set('call_issued_time', datetime.datetime.now().isoformat())
    del microservice_args['ms_use_currenttime_as_updated']

    # collect args_to_forward from url_args and request_args giving the latter higher precedence
    args_to_forward = {}
    for key, value in url_args.items():
        if key not in microservice_args:
            args_to_forward.setdefault(key, value[0])
    for key, value in request_args.items():
        if key not in microservice_args:
            args_to_forward[key] = value[0]

    if microservice_args.get('ms_pagenum_param_at_src') and args_to_forward.get(
            microservice_args.get('ms_pagenum_param_at_src')):
        microservice_args['do_page'] = True
    if 'since' in urllib.parse.parse_qs(parsed_url[3]):
        microservice_args['ms_since_param_at_src'] = 'since'
    if 'limit' in urllib.parse.parse_qs(parsed_url[3]):
        microservice_args['ms_since_param_at_src'] = 'limit'

    if since:
        if microservice_args.get('ms_since_param_at_src'):
            args_to_forward[microservice_args.get('ms_since_param_at_src')] = since
        if '__since__' in url:
            logger.debug('Since is {}, with the value {}'.format(str(type(since)), since))
            regex_iso_date_format = '^\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d(\.\d{0,7}){0,1}([+-][0-2]\d:[0-5]\d|Z)?'
            try:
                if re.match(regex_iso_date_format, since):
                    logger.debug("SINCE IS A ISO DATE: {}".format(since))
                    since = urllib.parse.quote(since)
                elif isinstance(int(since), int):
                    logger.debug("SINCE IS A VALID INT: {}".format(since))
                    if microservice_args.get('ms_offset_bigger_and_equal'):
                        since = str(int(since) + 1)
            except Exception as ex:
                logging.error(error_handling())
            url = url.replace('__since__', since)
            logger.debug("URL WITH SINCE:{}".format(url))
    else:
        logger.debug("URL WITHOUT SINCE:{}".format(url))
    if limit:
        if microservice_args.get('ms_limit_param_at_src'):
            args_to_forward[microservice_args.get('ms_limit_param_at_src')] = limit
        if '__limit__' in url:
            url = url.replace('__limit__', limit)
        if limit and not microservice_args.get('ms_limit_param_at_src'):
            microservice_args[limit] = int(limit)

    # Fields used to do multiple requests if there is a page and offset needed.
    page_size_attributes = ["ms_loop_request_pagesize_attribute", "ms_loop_request_total_attribute",
                            "ms_loop_request_offset_arg", "ms_loop_request_offset_attribute"]
    page_size_attributes_length = len(page_size_attributes)
    missing_page_size_attributes = [e for e in page_size_attributes if not microservice_args.get(e)]
    if len(missing_page_size_attributes) != page_size_attributes_length and len(missing_page_size_attributes) != 0:
        # There's not enough arguments to actually do this, give exception.
        raise Exception(f'Cannot loop the request because we are missing fields {missing_page_size_attributes}')
    elif len(missing_page_size_attributes) == 0:
        microservice_args['do_loop_request'] = True

    logger.debug(url)
    logger.debug(microservice_args)
    logger.debug(args_to_forward)
    return url, microservice_args, args_to_forward


@app.route("/<path:path>", methods=["GET"])
def get_data(path):
    try:
        url, microservice_args, args_to_forward = parse_qs(request)
        response_data = generate_response_data(url, microservice_args, args_to_forward)
        return Response(response=response_data)
    except Exception as e:
        exception_str = error_handling()
        logging.error(exception_str)
        return abort(500, exception_str)


if __name__ == '__main__':
    # Set up logging
    logger = log.init_logger('incremental-jsonsystem', os.getenv('LOGLEVEL', 'INFO'))

    FULL_URL_PATTERN = get_var('FULL_URL_PATTERN')
    UPDATED_URL_PATTERN = get_var('UPDATED_URL_PATTERN')
    UPDATED_PROPERTY = get_var('UPDATED_PROPERTY')
    OFFSET_BIGGER_AND_EQUAL = get_var('OFFSET_BIGGER_AND_EQUAL')
    UPDATED_PROPERTY_FROM_FORMAT = get_var('UPDATED_PROPERTY_FROM_FORMAT')
    UPDATED_PROPERTY_TO_FORMAT = get_var('UPDATED_PROPERTY_TO_FORMAT')
    auth_type = get_var('AUTHENTICATION')
    config = json.loads(get_var('CONFIG'))
    if UPDATED_PROPERTY_TO_FORMAT and not UPDATED_PROPERTY_FROM_FORMAT:
        logger.error('Cannot set UPDATED_PROPERTY_TO_FORMAT without setting UPDATED_PROPERTY_FROM_FORMAT. Exiting.')
        exit(-1)
    print('STARTED UP WITH:')
    print(f'\tFULL_URL_PATTERN={FULL_URL_PATTERN}')
    print(f'\tUPDATED_URL_PATTERN={UPDATED_URL_PATTERN}')
    print(f'\tUPDATED_PROPERTY={UPDATED_PROPERTY}')
    print(f'\tUPDATED_PROPERTY_FROM_FORMAT={UPDATED_PROPERTY_FROM_FORMAT}')
    print(f'\tUPDATED_PROPERTY_TO_FORMAT={UPDATED_PROPERTY_TO_FORMAT}')
    print(f'\tOFFSET_BIGGER_AND_EQUAL={OFFSET_BIGGER_AND_EQUAL}')
    print(f'\tauth_type={auth_type}')
    if not auth_type:
        SYSTEM = OpenUrlSystem(config)
    elif auth_type.upper() == 'OAUTH2':
        SYSTEM = Oauth2System(config)

    if os.environ.get('WEBFRAMEWORK', '').lower() == 'flask':
        app.run(debug=True, host='0.0.0.0', port=int(
            os.environ.get('PORT', 5000)))
    else:
        import cherrypy

        app = log.add_access_logger(app, logger)
        cherrypy.tree.graft(app, '/')

        # Set the configuration of the web server to production mode
        cherrypy.config.update({
            'environment': 'production',
            'engine.autoreload_on': False,
            'log.screen': True,
            'server.socket_port': int(os.environ.get("PORT", 5000)),
            'server.socket_host': '0.0.0.0'
        })

        # Start the CherryPy WSGI web server
        cherrypy.engine.start()
        cherrypy.engine.block()
        # app.run(threaded=True, debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
