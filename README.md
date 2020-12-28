# mail-server installation instructions for Ubuntu.

This installation process uses both Docker and external Nginx / Certbot. This was done so that other products could be installed on the same server.

## Docker installation

```
sudo apt-get remove docker docker-engine docker.io containerd runc
sudo apt-get update
sudo apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg-agent \
    software-properties-common \
    git \
    nano
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
```

# the fingerprint must be equal to 9DC8 5822 9FC7 DD38 854A  E2D8 8D81 803C 0EBF CD88, .
# check that by searching for its last characters:
`sudo apt-key fingerprint 0EBFCD88`
# now add the repo:
```
sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
```
# install docker:
```
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io
```
# install docker-compose:
```
sudo curl -L "https://github.com/docker/compose/releases/download/1.25.5/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```
# in caseof problems use https://docs.docker.com/compose/install/

# Install git

Use your name and email here:
```
sudo apt-get install git
sudo git config --global user.email "gleki.is.my.name@gmail.com"
sudo git config --global user.name "lagleki"
```
# Install Nginx
```
sudo apt-get install nginx -y
sudo apt-get update
sudo apt-get install software-properties-common -y
sudo add-apt-repository universe
sudo add-apt-repository ppa:certbot/certbot
sudo apt-get update
sudo apt-get install certbot python-certbot-nginx -y
```
Let's create a username-password pair to protect various routes. Instead of myuser, enter your login, generate a password at https://passwordsgenerator.net/ and write it out somewher (will need later):
```
sudo sh -c "echo -n 'myuser:' >> /etc/nginx/.htpasswd"
sudo sh -c "openssl passwd -apr1 >> /etc/nginx/.htpasswd"
```
You will be asked for your password 2 times.

Then check that the login and the hashed password got written to the file:
`cat /etc/nginx/.htpasswd`

# Choosing domains

Let's say we want 

* a mail server domain mail_service.lojban.com - we want the SMTP access there (like maili_service.lojban.org:465), POP access and our dashboard there. *Do not use a second order domain, only third (or more) order domains are allowed !!!*
* and we want out mailboxes at admin@lojban.org, support@lojban.org, user@jbotcan.org. Those wil also serve as logins that you will need to enter while configuring those mailboxes. *Notice that for all those mailboxes the mail server domain is still the same and is equal to `mail_service.lojban.com` !!!*

# Optionally install Cloudflare for your lojban.com, lojban.org, jbotcan.org etc. hosts.

# DNS records

Fill in DNS-records for lojban.com. *Turn off Cloudflare proxy for each of the recrds below!!!*

```
# Name              Type       Value
mailing_server      A       1.2.3.4# ip-address of the server you will have Mailcow on
autodiscover        CNAME   mail_service.lojban.com
autoconfig          CNAME   mail_service.lojban.com
@                   MX 10   mail_service.lojban.com # MX record with priority 10
```
Oen your hosting admin dashboard (Hetzner, Leaseweb), set your reverse DNS record equal to `mail_service.lojban.com`.

# Install Mailcow

* `umask` below must be equal to `0022`. Check out https://mailcow.github.io/mailcow-dockerized-docs/
 for troubleshooting.
```
cd /opt
sudo git clone https://github.com/mailcow/mailcow-dockerized
cd mailcow-dockerized
sudo chown -R gleki: /opt/mailcow-dockerized
```

* generate (without sudo) your mailcow config file:
** When asked about the domain enter: `mail_service.lojban.com`
** timezone - UTC

`sudo ./generate_config.sh`

# edit your confi file using any editor (vim, nano or others). (If it appears to be empty it means we generated it using sudo, then delete the file and generate it again properly):
`sudo nano mailcow.conf`

# Mailcow config breakdown

```
# ------------------------------
# mailcow web ui configuration
# ------------------------------
# example.org is _not_ a valid hostname, use a fqdn here.
# это логин и пароль админа в админке, использовать их, затем поменять при первом входе и выписать
# Default Mailcow dashboard UI admin user is "admin", default password is "moohoo". Use them while entering the dashboard the first tim, after that change them and write out to a safe location.

# your mailserver domain:
MAILCOW_HOSTNAME=mailing_service.lojban.com

# ------------------------------
# SQL database configuration
# ------------------------------

# this is the name of the MySQL database where letters will be stored:еgener
DBNAME=mailcow
DBUSER=mailcow

# Please use long, random alphanumeric strings (A-Za-z0-9), e.g. use https://passwordsgenerator.net/
DBPASS=k294nYGwYeTySa753ISQeqbWSBsT
DBROOT=5gHBDkV98GNyE8dR7OGYmQFRXrtu

# ------------------------------
# HTTP/S Bindings
# ------------------------------

# You should use HTTPS, but in case of SSL offloaded reverse proxies:
# Might be important: This will also change the binding within the container.
# If you use a proxy within Docker, point it to the ports you set below.
# IMPORTANT: Do not use port 8081, 9081 or 65510!

# HTTP_PORT is the port that your external (out of the docker) Nginx will listen to. See instructions after the mailcow config file. Just choose a free port in your host system. Same for HTTPS_PORT

HTTP_PORT=8080
HTTP_BIND=0.0.0.0

HTTPS_PORT=8443
HTTPS_BIND=0.0.0.0

# ------------------------------
# Other bindings
# ------------------------------
# You should leave that alone
# Format: 11.22.33.44:25 or 0.0.0.0:465 etc.
# Do _not_ use IP:PORT in HTTP(S)_BIND or HTTP(S)_PORT

# ports below must be free on the host system, use `sudo netstat -tulpen` to make sure they are free

SMTP_PORT=25
SMTPS_PORT=465
SUBMISSION_PORT=587
IMAP_PORT=143
IMAPS_PORT=993
POP_PORT=110
POPS_PORT=995
SIEVE_PORT=4190
DOVEADM_PORT=127.0.0.1:19991
SQL_PORT=127.0.0.1:13306
SOLR_PORT=127.0.0.1:18983
REDIS_PORT=127.0.0.1:7654

# Your timezone

# better put your timezone as UTC
TZ=UTC

# Fixed project name

COMPOSE_PROJECT_NAME=mailcowdockerized

# Set this to "allow" to enable the anyone pseudo user. Disabled by default.
# When enabled, ACL can be created, that apply to "All authenticated users"
# This should probably only be activated on mail hosts, that are used exclusivly by one organisation.
# Otherwise a user might share data with too many other users.
ACL_ANYONE=disallow

# Garbage collector cleanup
# Deleted domains and mailboxes are moved to /var/vmail/_garbage/timestamp_sanitizedstring
# How long should objects remain in the garbage until they are being deleted? (value in minutes)
# Check interval is hourly

MAILDIR_GC_TIME=1440

# Additional SAN for the certificate
#
# You can use wildcard records to create specific names for every domain you add to mailcow.
# Example: Add domains "example.com" and "example.net" to mailcow, change ADDITIONAL_SAN to a value like:
#ADDITIONAL_SAN=imap.*,smtp.*
# This will expand the certificate to "imap.example.com", "smtp.example.com", "imap.example.net", "imap.example.net"
# plus every domain you add in the future.
#
# You can also just add static names...
#ADDITIONAL_SAN=srv1.example.net
# ...or combine wildcard and static names:
#ADDITIONAL_SAN=imap.*,srv1.example.com
#

ADDITIONAL_SAN=

# Skip running ACME (acme-mailcow, Let's Encrypt certs) - y/n

SKIP_LETS_ENCRYPT=n

# Create seperate certificates for all domains - y/n
# this will allow adding more than 100 domains, but some email clients will not be able to connect with alternative hostnames
# see https://wiki.dovecot.org/SSL/SNIClientSupport
ENABLE_SSL_SNI=n

# Skip IPv4 check in ACME container - y/n

SKIP_IP_CHECK=n

# Skip HTTP verification in ACME container - y/n

SKIP_HTTP_VERIFICATION=n

# Skip ClamAV (clamd-mailcow) anti-virus (Rspamd will auto-detect a missing ClamAV container) - y/n

# if you need an antivuris for your letter put `n`, if not needed or we want to save RAM then put `y`
SKIP_CLAMD=y

# Skip SOGo: Will disable SOGo integration and therefore webmail, DAV protocols and ActiveSync support (experimental, unsupported, not fully implemented) - y/n

SKIP_SOGO=n

# Skip Solr on low-memory systems or if you do not want to store a readable index of your mails in solr-vol-1.

# if we wat to have indices of all the letters put `n`. want save RAM? put `y`
SKIP_SOLR=y

# Solr heap size in MB, there is no recommendation, please see Solr docs.
# Solr is a prone to run OOM and should be monitored. Unmonitored Solr setups are not recommended.

SOLR_HEAP=1024

# Enable watchdog (watchdog-mailcow) to restart unhealthy containers (experimental)

USE_WATCHDOG=n

# Allow admins to log into SOGo as email user (without any password)

ALLOW_ADMIN_EMAIL_LOGIN=n

# Send notifications by mail (sent from watchdog@MAILCOW_HOSTNAME)
# CAUTION:
# 1. You should use external recipients
# 2. Mails are sent unsigned (no DKIM)
# 3. If you use DMARC, create a separate DMARC policy ("v=DMARC1; p=none;" in _dmarc.MAILCOW_HOSTNAME)
# Multiple rcpts allowed, NO quotation marks, NO spaces

#WATCHDOG_NOTIFY_EMAIL=a@example.com,b@example.com,c@example.com
#WATCHDOG_NOTIFY_EMAIL=

# Notify about banned IP (includes whois lookup)
WATCHDOG_NOTIFY_BAN=y

# Checks if mailcow is an open relay. Requires a SAL. More checks will follow.
# https://www.servercow.de/mailcow?lang=en
# https://www.servercow.de/mailcow?lang=de
# No data is collected. Opt-in and anonymous.
# Will only work with unmodified mailcow setups.
WATCHDOG_EXTERNAL_CHECKS=n

# Max log lines per service to keep in Redis logs

LOG_LINES=9999

# Internal IPv4 /24 subnet, format n.n.n (expands to n.n.n.0/24)

IPV4_NETWORK=172.22.1

# Internal IPv6 subnet in fc00::/7

IPV6_NETWORK=fd4d:6169:6c63:6f77::/64

# Use this IPv4 for outgoing connections (SNAT)

#SNAT_TO_SOURCE=

# Use this IPv6 for outgoing connections (SNAT)

#SNAT6_TO_SOURCE=

# Create or override an API key for the web UI
# You _must_ define API_ALLOW_FROM, which is a comma separated list of IPs
# An API key defined as API_KEY has read-write access
# An API key defined as API_KEY_READ_ONLY has read-only access
# Allowed chars for API_KEY and API_KEY_READ_ONLY: a-z, A-Z, 0-9, -
# You can define API_KEY and/or API_KEY_READ_ONLY
# Using CIDR is not yet implemented within mailcow.conf, use the UI to allow networks.

#API_KEY=
#API_KEY_READ_ONLY=
#API_ALLOW_FROM=172.22.1.1,127.0.0.1

# mail_home is ~/Maildir
MAILDIR_SUB=Maildir

# SOGo session timeout in minutes
SOGO_EXPIRE_SESSION=480
```

# Fire up Mailcow:

```
sudo docker-compose pull
sudo docker-compose up -d
```
# External (out of the docker file) Nginx config: 

`sudo nano /etc/nginx/sites-enabled/default`

A sample below:
* enter the proper mailserver domain (change `mail_service.lojban.com` to your mailserver domain).
* 8080 below corresponds HTTP_PORT from the mailcow.conf file above so change accordingly.

```
server {
  listen 80 default_server;
  listen [::]:80 default_server;
  server_name mail_service.lojban.com autodiscover.* autoconfig.*;
  return 301 https://$host$request_uri;
}
server {
  listen 443 ssl http2;
  listen [::]:443 ssl http2;
  server_name mail_service.lojban.com autodiscover.* autoconfig.*;

  ssl_certificate /opt/mailcow-dockerized/data/assets/ssl/cert.pem;
  ssl_certificate_key /opt/mailcow-dockerized/data/assets/ssl/key.pem;
  ssl_session_timeout 1d;
  ssl_session_cache shared:SSL:50m;
  ssl_session_tickets off;

  # See https://ssl-config.mozilla.org/#server=nginx for the latest ssl settings recommendations
  # An example config is given below
  ssl_protocols TLSv1.2;
  ssl_ciphers HIGH:!aNULL:!MD5:!SHA1:!kRSA;
  ssl_prefer_server_ciphers off;

  location /Microsoft-Server-ActiveSync {
    proxy_pass http://127.0.0.1:8080/Microsoft-Server-ActiveSync;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_connect_timeout 75;
    proxy_send_timeout 3650;
    proxy_read_timeout 3650;
    proxy_buffers 64 256k;
    client_body_buffer_size 512k;
    client_max_body_size 0;
  }

  location / {
    proxy_pass http://127.0.0.1:8080/;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 0;
    auth_basic "Restricted Content";
    auth_basic_user_file /etc/nginx/.htpasswd;
  }
}
```

Enable https and redirects:
`sudo certbot --nginx`

# Configuring mail sending domains
E.g. we'd like to have mail system enabled for jbotcan.org (the mailserver domain (SMTP/POP/dashboard) will still be the same: `mail_service.lojban.com`)

https://dkimcore.org/tools/keys.html - generate a DKIM key for `jbotcan.org` domain, copy the key from "Private key" section. A sample key (so that you get an idea what it looks like):

```
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDzr/10HELgdf9iIQ7RO59O7TaTUJX+7AjSST9prdtGFs1T3O2B
HEY/sYciG+7SNAYmHWEehe0POLwSdXEdP2UG6pPdvFiU5l3mBRQx8gwef4/bqKdi
vOZaOyvALwNclLUDiU8EISZAa94es84jKGx2VbFy8ZItdkPVlTJzMiz/sQIDAQAB
AoGAVCr5M91/C+A1sUMRxxr8z1oHe6Jd7IrCET/Tc0Dld7Pwf4LTVcDaUq2SqylS
t6/YX9nN7aj8VEGVYBfUVfHLhod9GB4GhbkAiNXzfeNXlN1FZoqMwe97wPt74wcP
5VunA8KcDB6cLxlEYxOt4aS5B5we4maoOGKsRakylThmvzECQQD6qPiAL8foelNd
nN68XOSwk9u7GdkNtKqKJgKDUSUCLO4P/r7HxybaM4UeSWWfisc7/Ppd5fEkcX3W
Kz7R4vb3AkEA+OD+K8DkhU4WOPJfkqGbYGXbpdvt4hE+4JpF5Kmd/t8guD3Idovd
qG1A9nO3TsQj2IjVV0W3NkO0YFfKcORMlwJAQRPTiLxfA32W3UwYDAF2Il4RA0+f
qc5JJJrftiZAHIN7v01dTNLoxGfx3L4jkztdpLZ2biB/7f1FNXB+29E4WwJBAJdI
RJgaB47UeYOiKOA75fPB1rNKLZ6Wdw8WF9g4Fncf8Iat35XXzSQdTTjB/DIf3d44
xt4Nww6dNx69Hqxiyf8CQQC2AFOnSfqVLTZeBiqJE4x62NNM69dDJSqxH7T+6coB
YRVymf5osps3frDIWGemhWP2jJ13qeIa3pp7IXBqK7+r
-----END RSA PRIVATE KEY-----
```

Open Mailcow dashboard at https://mail-service.lojban.com/mailbox, add a new domain `jbotcan.org`

Next: Mailcow => https://mail-service.lojban.com/admin#dkim => "ARC/DKIM" tab

Import private key: domain “jbotcan.org“, selector “dkim”, enter the private key. Press "Import"

You should get a green success message popup.

At the top of the pae you will have an instruction what to add to DNS records of `jbotcan.org`. If your selector is “dkim”, then add for jbotcan.org the DNS-record jbotcan.org of type TXT,  `Name=”dkim._domainkey”`, the value is to be taken from Mailcow.

Turn off Cloudflare proxy for eac of the record below!!!

```
# Name              Type       Value
autodiscover        CNAME   mail-service.lojban.com
autoconfig          CNAME   mail-service.lojban.com
@                   MX 10   mail-service.lojban.com # MX with priority 10
@                   TXT     v=spf1 mx ~all
_dmarc              TXT     "v=DMARC1; p=reject; rua=mailto:admin@jbotcan.org" # enter without the quotation marks, this is the mail address you will get service reports to from Gmail etc.
dkim._domainkey  TXT     "v=DKIM1; k=rsa; t=s; s=email; p=..." # enter without the quotation marks, this is thevalue from Mailcow dashboard (ssee above)
@                   TXT     "google-site-verification=..." # optional: enter without the quotation marks, Gmail postmaster can be added by following corresponding Gmail postmaster instructions, see Google documentation
```
Open https://mail-service.lojban.com/mailbox - for jbotcan.og pess on DNS button. Make sure that all the records are okay. Ignore DMARC and SPF values. SRV, TLSA records can be used for more security, you may ignore them too, for the others you must see a green "success" tick.

# Installing mailboxes

So we have jbotcan.org domain. Let's install for it a new mailbox admin@jbotcan.og

Open Mailcow https://mail-service.lojban.com/mailbox, section "Mailboxes".

Username - admin

Write out "admin" and its password.
Let's check: open https://mail-service.lojban.com/SOGo/ client

login - admin@jbotcan.org

# Use forwarding to Gmail and similar services.

checked for Gmail.

Create in Mailcow a new mailbox or use an existing one, e.g. admin@jbotcan.org.

Open  Gmail > Settings > Accounts and import

For sending mails enter admin@jbotcan.org,

Server must be automatically detected as mail-service.lojban.com

login - admin@jbotcan.org. i.e. write in full, the full "email"  !!!

port 465 - only SSL

For receiving mails enter admin@jbotcan.org,

Server - enter mail-service.lojban.com manually.

login - admin@jbotcan.org. i.e. write in full, the full "email"  !!!

Only accept mails via SSL

port 995
