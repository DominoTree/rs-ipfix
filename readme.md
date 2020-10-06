# rs-ipfix

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Crates.io Version](https://img.shields.io/crates/v/ipfix.svg)](https://crates.io/crates/ipfix)

This is a library to parse IPFIX/Netflow v10 (RFC7011) data with functionality to export it as JSON.

An example app using this library to send data to Elasticsearch is available at https://gitlab.com/dominotree/ipfix-elasticsearch

There is a fair bit of cleanup and optimization that needs to be done here, but it should currently be fully functional and capable of processing a large number of flows.
