Overview
========

`ngx_hashtld` is a module that converts a given APNIC experiment string into a
new domain picked from a provided list, by hashing the experiment string into
an index for the array/list.

Build
=====

  * Configure and nginx with `--add-module=path/to/ngx_hashtld`

Technique
=========

Read list of Domains from file.
Construct experiment string from nginx variables
(e.g) 6du-u$txrnd-c$ccid-s$txsec-i$txad-0
then hash it and use the resukting integer as the lookup index into the domain
list.
