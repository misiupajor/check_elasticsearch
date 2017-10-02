# check_elasticsearch

This plugin aims to monitor Elasticsearch by allowing you to run queries on a _specific_ or _all_ indexes. The data returned will be a count (integer) and will also be graphed accordingly. It's intention is to graph counts (=matches) based on queries you define.

This plugin is compatible with Elasticsearch 0.5x, Nagios / Naemon, but also OP5's broadend offering: ESLog.

## Installation

Python dependencies that are required can be installed as follows:
```sh
$ pip install docopt elasticsearch
```

Configure Elasticsearch to bind on all available interfaces (or as specific interface, but that's not covered below):

Edit: /etc/elasticsearch/elasticsearch.yml to read following:
```sh
network.host: 0.0.0.0
```

Instead of the default, which is:
```sh
network.host: 127.0.0.1
```

## Examples

The plugin allows you to fetch logs matching either a **query** or a **filter**.

Retrieve a count that matches a **query** with syntax example:

```sh
check_elasticsearch.py --host <host> --index <index> --query <query> --warning <warning> --critical <critical>
```

**Query example** using the query mode:
```sh
check_elasticsearch.py --host "http://<elasticsearch ip>:9200/" --index "filebeat-*" --query "system_process_id=148" --warning 1 --critical 2
```

Retrieve a count matching a saved _Kibana_ filter with syntax example:

```sh
$ check_elasticsearch.py --host <host> --filter <query> --warning <warning> --critical <critical>
```

**Filter example** using the filter mode:
```sh
$ check_elasticsearch.py --host "http://<elasticsearch ip>:9200/" --filter "some_saved_filter_in_kibana" --warning 1 --critical 2
```


## Contributions
Thanks goes to these wonderful people:

* Oskar Rittsel ([@OP5](https://www.op5.com))