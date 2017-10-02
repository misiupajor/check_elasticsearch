#!/usr/bin/python
"""Usage:
    check_elasticsearch.py --host <host> --index <index> --query <query> --warning <warning> --critical <critical>
    check_elasticsearch.py --host <host> --filter <query> --warning <warning> --critical <critical>

    DEPENDENCIES:
        pip install docopt elasticsearch

    Arguments:
        HOST    Endpoint to Elasticsearch, eg. http://<ip>:<port>
        INDEX   Elastic index to use, eg. rsyslog-* or filebeat-*. Use _all to search all indexes (more resource intensive)
        QUERY   Raw Elastic/Lucene query, eg. "received_from=10.0.5.2 and program=systemd and host=10.0.5.10 and @timestamp: [now-5h TO now]"
        FILTER  Name of saved filter in Kibana, its index will be used automatically.
        WARNING Threshold as integer. eg. 128
        CRITICAL Threshold as integer. eg. 299

    Examples:
         check_elasticsearch.py --host "http://<elastic ip>:9200/" --index "filebeat-*" --query "system_process_id=148" --warning 1 --critical 2
         check_elasticsearch.py --host "http://<elastic ip>:9200/" --filter "some_saved_filter_in_kibana" --warning 1 --critical 2


"""
__author__ = 'Misiu Pajor, OP5 AB'
__date__ = '2017-10-02'
__version__ = '0.6.2'

try:

    from docopt import docopt
    from elasticsearch import Elasticsearch
    from elasticsearch.exceptions import ConnectionError, \
        TransportError, \
        ConnectionTimeout, \
        NotFoundError, \
        RequestError
    import json
except ImportError as missing:
    print (
        'Error - could not import all required Python modules\n"%s"'
        % missing + '\nDependency installation with pip:\n'
        '"# pip install docopt elasticsearch"')
    exit(3)

class ElasticAPI(object):
    def __init__(self):
        self.args = docopt(__doc__, version=None)
        self.url = self.args["<host>"]
        self.username = ""
        self.password = ""
        try:
            self.es = Elasticsearch(
                [ self.url ],
                sniff_on_start=True,
                timeout=60,
            )
        except (ConnectionTimeout, ConnectionError, TransportError, NotFoundError, RequestError) as error:
            exit("Error: Exception: {0}".format(error))

    ''' queries elasticsearch to find saved filter as argumented in get_filter() '''
    def _find_filter(self, filter):
        json = self.es.search(index="_all", body={"query":{"query_string":{"query":filter}}})
        try:
            data = json["hits"]["hits"][0]["_source"]["kibanaSavedObjectMeta"]["searchSourceJSON"]
        except KeyError:
            exit("Error: Filter {0} could not be found.".format(filter))
        return data

    ''' find saved filters in kibana by its given named in GUI  '''
    def get_filter(self, filter):
        data = json.loads(self._find_filter(filter))
        try:
            data["index"]
        except IndexError:
            exit("Error: No index could not be localised for the given filter.")
        query = data["query"]["query_string"]["query"]
        count = self.es.count(index=data["index"], body={"query":{"query_string":{"query":query}}})
        if count["count"] is not None:
            return count["count"]
        exit("Error: Query did not return any hits")

    ''' gets count for a given query (eg. "+@timestamp: [now-30m TO now] and +received_from:172.27.105.3)" '''
    def get_query(self, query, index=None):
        count = self.es.count(index=self.args["<index>"], body={"query":{"query_string":{"query":query}}})
        if count["count"] is not None:
            return count["count"]
        exit("Error: Query did not return any count data.")

    ''' determinates the exit_code and plugin_output '''
    def _exit_state(self, count):
        warning = int(self.args["<warning>"])
        critical = int(self.args["<critical>"])
        if count >= critical:
            message = "CRITICAL - Total hits: {0} | hits={0}".format(count)
            exit_code = 2
        elif count >= warning:
            message = "WARNING - Total hits: {0} | hits={0}".format(count)
            exit_code = 1
        else:
            message = "OK - Total hits: {0} | hits={0}".format(count)
            exit_code = 0
        if message:
            print message
        exit(exit_code)

if __name__ == '__main__':
    elastic = ElasticAPI()
    if elastic.args["--query"]:
        count = elastic.get_query(elastic.args["<query>"], elastic.args["<index>"])
    if elastic.args["--filter"]:
        count = elastic.get_filter(elastic.args["<query>"])
    elastic._exit_state(count)