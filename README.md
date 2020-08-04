# local-https-dev
- create self sign  SSL certificate for local development.


### Important!
```
* First time you start script it creates rootCA.crt and rootCA.key in ./config/ folder all
      domian certificates will be sign by this root.crt`
```

### HOW TO

- generate certificates:
    
```bash
    python3 ./cert_factory.py cert -d domain.com domain2.com
```
- add certificates to your nginx config:
```text
    # add this line`s to your nginx config.
    ssl_certificate /etc/nginx/ssl/domain.com.crt;
    ssl_certificate_key /etc/nginx/ssl/domain.com.key;
    ssl_client_certificate /etc/nginx/ssl/rootCA.crt;
```
- add rootCA.cert to browser authority.

### COMMANDS
```text
usage: 
    ./cert_factory.py <command> [<args>] -h 
        The most commonly used commands are:
        - cert: 
              
              #first rootCA,key, and rootCA.crt from User input,
              #then from default dirs and only then
              optional arguments:
              -h, --help            show this help message and exit
              -rK ROOTKEY, --rootKey ROOTKEY
              -rCA ROOTCERTIFICATE, --rootCertificate ROOTCERTIFICATE
              -d DOMAIN [DOMAIN ...], --domain DOMAIN [DOMAIN ...]
              -o OUTPUT, --output OUTPUT
              --common_name COMMON_NAME
              --country_name COUNTRY_NAME
              --locality_name LOCALITY_NAME
              --organization_name ORGANIZATION_NAME
              --state_or_province_name STATE_OR_PROVINCE_NAME

        - root:
            optional arguments:
              -h, --help            show this help message and exit
              -o OUTPUT, --output OUTPUT
              --common_name COMMON_NAME
              --country_name COUNTRY_NAME
              --locality_name LOCALITY_NAME
              --organization_name ORGANIZATION_NAME
              --state_or_province_name STATE_OR_PROVINCE_NAME


```
