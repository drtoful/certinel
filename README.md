# certinel

Certinel is a small utility that let's you monitor the validity and status of your SSL/TLS enabled websites.

It has been created, because currently [Let's encrypt](https://letsencrypt.org) certificates are only valid for 90 days and there's no automation or monitoring currently available to check. You can do automation with some cronjobs, but this is probably unreliable so it's better you monitor the status of your certificates. Certinel helps you with that. 

Certinel also provides a simple one-page monitoring page were you can add, remove and check the status of your domains.

## Building

    go get -u github.com/jteeuwen/go-bindata/...
    go get github.com/drtoful/certinel
    go generate github.com/drtoful/certinel
    go install github.com/drtoful/certinel

## Running

You can just run certinel by invoking it's binary in your $GOPATH/bin. This will also start a simple webserver on port 8080 to which you can connect and edit the domains you want to monitor. If you want to use the API have a look at the API documentation.

### Command line options

    -db="certinel.db": path to the database store
    -port="8080": port for api server

## License

Certinel is licensed under the BSD License. See LICENSE for more information.

### Third-Party Libraries

If you are the owner of one of the following libraries and the license information is incorrect, please feel free to contact me in order to update this list.

* github.com/boltdb/bolt: MIT License
* github.com/codegangsta/negroni: MIT License
* github.com/gorilla/context: BSD License
* github.com/gorilla/mux: BSD License
* github.com/miekg/dns: BSD License
* github.com/jteeuwen/go-bindata: CC0 1.0 Public Domain

* [bootstrap](http://getbootstrap.com): MIT License
* [font-awesome](http://fortawesome.github.io): SIL OFL 1.1 / MIT License
* github.com/afarkas/html5shiv: MIT License
* github.com/scottjehl/Respond: MIT License
* [jquery](https://jquery.com): jQuery License
* [moment.js](http://momentjs.com): MIT License
* [angular.js](https://angularjs.org): MIT License

