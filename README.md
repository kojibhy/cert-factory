# Certificate Factory

- create self sign SSL certificate for domains in local development.
- create Root Authority's for domains in local development.

## Install

- install script

```bash
$  git clone https://github.com/kojibhy/cert-factory && cd cert-factory && ./install.sh
```

### HOW TO

- create Self Sign Certificates

```bash
$ ./certfactory.py sign -d domain.com
```

### Important!

```text
* The first time you start the script it creates ./certificates/ folder where store rootCA.crt and rootCA.key and all domain certificates will be signed by this root.crt`
```

```text
optional arguments:
  -h, --help            show this help message and exit
  --certificates-dir CERTIFICATES_DIR
  -d DOMAIN [DOMAIN ...], --domain DOMAIN [DOMAIN ...]
  --rKey RKEY
  --rCert RCERT
  --commonName COMMONNAME
                        commonName
  --countryName COUNTRYNAME
                        countryName
  --localityName LOCALITYNAME
                        localityName
  --stateOrProvinceName STATEORPROVINCENAME
                        stateOrProvinceName
  --streetAddress STREETADDRESS
                        streetAddress
  --organizationName ORGANIZATIONNAME
                        organizationName
  --organizationalUnitName ORGANIZATIONALUNITNAME
                        organizationalUnitName
  --serialNumber SERIALNUMBER
                        serialNumber
  --surname SURNAME     surname
  --givenName GIVENNAME
                        givenName
  --title TITLE         title
```

- create Root Authority's:

```text

  $ ./certfactory.py create 


optional arguments:
  -h, --help            show this help message and exit
  --certificates-dir CERTIFICATES_DIR
  --commonName COMMONNAME
                        commonName
  --countryName COUNTRYNAME
                        countryName
  --localityName LOCALITYNAME
                        localityName
  --stateOrProvinceName STATEORPROVINCENAME
                        stateOrProvinceName
  --streetAddress STREETADDRESS
                        streetAddress
  --organizationName ORGANIZATIONNAME
                        organizationName
  --organizationalUnitName ORGANIZATIONALUNITNAME
                        organizationalUnitName
  --serialNumber SERIALNUMBER
                        serialNumber
  --surname SURNAME     surname
  --givenName GIVENNAME
                        givenName
  --title TITLE         title

```

- add certificates to your nginx config:

```text
    # add this line`s to your nginx config.
    ssl_certificate /etc/nginx/ssl/domain.com.crt;
    ssl_certificate_key /etc/nginx/ssl/domain.com.key;
    ssl_client_certificate /etc/nginx/ssl/rootCA.crt;
```

- add rootCA.cert to browser authority.

### dnsmasq setup

- install dnsmasq

```text
apt install dnsmasq
```

- configure dnsmasq
  ``
  chmod +x dnsmasq-install.sh && ./dnsmasq-install.sh
  ``
- create new config file for domain in /etc/dnsmasq.d/

```text
# cat /etc/dnsmasq.d/domain.com.conf
address=/domain.com/0.0.0.0
```