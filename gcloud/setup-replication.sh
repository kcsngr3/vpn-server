#!/bin/bash
# usage: ./setup-replication.sh netherlands 1.2.3.4 iowa 5.6.7.8

REGION_A=$1
IP_A=$2
REGION_B=$3
IP_B=$4

docker exec -i pg-central psql -U vpnadmin -d vpndb << EOF

-- subscribe to netherlands regional (same VM via docker bridge)
CREATE SUBSCRIPTION sub_${REGION_A}
  CONNECTION 'host=172.17.0.1 port=5432 dbname=vpndb 
              user=replicator password=replsecret'
  PUBLICATION vpn_publication;

-- subscribe to iowa (remote VM)
CREATE SUBSCRIPTION sub_${REGION_B}
  CONNECTION 'host=${IP_B} port=5432 dbname=vpndb 
              user=replicator password=replsecret'
  PUBLICATION vpn_publication;

-- verify
SELECT subname, subenabled FROM pg_subscription;
EOF