# SSLCheck_SAP

## Requirements

`pip install -r requirements.txt`

`-L --local` Flag to enable local server check
`-f --crtFile` Full path of SSL certificate file on local server
`-R --remote` Flag to enable remote server check
`-h --host `Hostname of remote server
`-p --port` Port number of remote server
`-I --info` Displays extra information about SSL certificate

## To run for local SSL certificate check:
```
$ python3 test.py -L -f /etc/ssl/certs/ca-certificates.crt
>>> -------------------------------------------------------------------
Expiry Date :  31/12/2030
----> INFO
3945 days left
```

## To run for local SSL certificate check with additional information:
```
$ python3 test.py -L -I -f /etc/ssl/certs/ca-certificates.crt
```

## To run for remote SSL certificate check:
```
$ python3 test.py -R -H 'github.com' -p 443
>>> Expiry Date :  03/06/2020
----> INFO
82 days left
```

## To run for remote SSL certificate check with additional Information:
```
$ python3 test.py -I -R -H 'github.com' -p 443
>>> Issued Domain Name : github.com
Country Name : US
Organization Name : DigiCert Inc
Organizational Unit Name : www.digicert.com
Common Name : DigiCert SHA2 Extended Validation Server CA

Expiry Date :  03/06/2020
----> INFO
82 days left
```
