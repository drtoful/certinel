API
===

Certinel provides a simple API to add, remove and check the status of monitoring jobs for domains. This is a short documentation about all endpoints.

GET /api/domains
----------------

**Arguments**: none

Get a list of all monitoring jobs currently active and their last status as a list. The returned list has the following format

    [
       {
          domain: <string>,
          port: <string>,
          status: {
              valid: <bool>,
              valid_days: <int>,
              last_check: <string>,
              last_error: <string>,
              check_duration: <int>
          }
       }, ...
    ]

The field *check_duration* is given in milliseconds. The field *last_check* always contains a UTC timestamp in RFC3339 form.

PUT /api/domains
----------------

**Arguments**: none

This adds a new monitoring job for a domain and port. You have to provide the following information as JSON document within the request:

    {
       domain: <string>,
       port: <string>,
    }

DELETE /api/domains
-------------------

**Arguments**:
 - *domain*: the domain you wish to delete
 - *port*: the associated port to this domain

Removes all monitoring data for this domain and port. This also stops any currently running monitoring jobs for this domain.

GET /api/certs
--------------

**Arguments**:
 - *domain*: the domain you wish to delete
 - *port*: the associated port to this domain

Get the current certificate stored for this domain, as well as a history of up to 50 certificates that this domain had in the past. The history is sorted by the validity period (NotAfter) in descending order (newest is first).

The returned object has the form:

    {
       current: <certificate>,
       history: [<certificate>, <certificate>, ...]
    }

The field *history* may be missing or empty. The object **certificate** has the format:

    {
       not_before: <string>,
       not_after: <string>,
       issuer: <subject>,
       subject: <subject>,
       serial: <string>,
       alternate_names: [<string>, <string>, ...],
       signature: {
           algorithm: <int>,
           value: <string>
       },
       fingerprints: <fingerprints>
    }

The field *alternate_names* may be empty. The field *fingerprints* contains a mapping from a hash algorithm (<string>) to the value (<string>). The object **subject** has the format:

    {
       cn: <string>;
       c: [<string>, <string>, ...],
       o: [<string>, <string>, ...],
       ou: [<string>, <string>, ...],
    }

The fields *c*, *o* and *ou* may be missing or empty.
