# check_elasticsearch

This plugin aims to monitor queries in Elasticsearch by allowing you to run a raw query on a _specific_ or _all_ indexes, or call a saved filter in Kibana.
The data returned will be a count (integer) and will also be graphed accordingly. It's intention is to graph counts (=matches) based on query/filter you define.

This plugin is compatible with Elasticsearch 5.x, Nagios / Naemon, but also OP5's broadend offering: ESLog.

## Installation

Python dependencies that are required can be installed as follows:
```sh
$ pip install docopt elasticsearch
```

Configure Elasticsearch to bind on all available interfaces (or as specific interface, but that's not covered below):

Edit: **/etc/elasticsearch/elasticsearch.yml** to read following:
```sh
network.host: 0.0.0.0
```

Instead of the default, which is:
```sh
# network.host: 192.168.0.1
```

## Examples

The plugin allows you to fetch logs matching either a **query** or a **filter**.

Retrieve a count that matches a **query** with syntax example:

```sh
$ check_elasticsearch.py --host <host> --index <index> --query <query> --warning <warning> --critical <critical>
```

**Query example** using the query mode:
```sh
$ check_elasticsearch.py --host "http://<elasticsearch ip>:9200/" --index "filebeat-*" --query "system_process_id=148" --warning 1 --critical 2
```

Retrieve a count matching a saved _Kibana_ filter with syntax example:

```sh
$ check_elasticsearch.py --host <host> --filter <query> --warning <warning> --critical <critical>
```

**Filter example** using the filter mode:
```sh
$ check_elasticsearch.py --host "http://<elasticsearch ip>:9200/" --filter "some_saved_filter_in_kibana" --warning 1 --critical 2
```

### Example output

```sh
$ check_elasticsearch.py --host "http://<elastic ip>:9200" --filter "some_saved_filter_in_kibana" --warning 200 --critical 400
WARNING - Total hits: 264 | hits=264
```

### Available arguments

For a list of available arguments, run this plugin with --help:

```sh
$ check_elasticsearch.py --help
Usage:
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

```

## Contributions
Thanks goes to these wonderful people:

* Oskar Rittsél ([@OP5](https://www.op5.com))
* Jörgen Bertholdsson ([@OP5](https://www.op5.com))
