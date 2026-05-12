#!/bin/bash
# usage: ./update-subscription.sh iowa 9.8.7.6

REGION=$1
NEW_IP=$2

docker exec -i pg-central psql -U vpnadmin -d vpndb << EOF
ALTER SUBSCRIPTION sub_${REGION}
  CONNECTION 'host=${NEW_IP} port=5432 dbname=vpndb 
              user=replicator password=replsecret';

SELECT subname, subenabled FROM pg_subscription;
EOF

# update firewall
gcloud compute firewall-rules update allow-pg-replication \
  --source-ranges=${NEW_IP}/32

echo "Subscription and firewall updated for $REGION → $NEW_IP"