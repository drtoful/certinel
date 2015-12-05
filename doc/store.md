Storage
=======

Certinel stores all data internally into a boltdb store. Following is a crude sketch to show how data is stored internally within this store:

    Bucket: "domains"
        Bucket: "<domain1>:<port1>"
            Value: "status"
            Value: "current"  => "cert~<serialnumber1>"
            Value: "cert~<serialnumber1>" => "raw certificate data"
            Value: "cert~<serialnumber2>" => "raw certicicate data"
            ...
            Value: "history~<NotBefore-RFC3339>" => "cert~<serialnumber1>"
            Value: "history~<NotBefore-RFC3339>" => "cert~<serialnumber2>"
            ...
            Value: "history~~" => "-- LIST STOP --"
        Bucket: "<domain1>:<port2>"
            ...
        Bucket: "<domain2>:<port1">
            ...

We use the value "history~~" as a way to specify the end of a list. That way we can quickly search for this key and reverse iterate over the list - bolt sorts in ascending order, so we need this trick to get a descending order. Also we use the NotBefore field of the certificate and convert this to a RFC3339 timestamp. This has then the advantage that it is ascii sortable (as the raw big integers from the serial number aren't). 
