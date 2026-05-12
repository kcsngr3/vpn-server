#!/bin/bash
# usage: ./register-server.sh netherlands 1.2.3.4 region
SERVER_ID=$1
SERVER_IP=$2
SERVER_REGION=$3

docker exec -i pg-region psql -U vpnadmin -d vpndb << EOF
INSERT INTO servers(server_id, ip, region)
VALUES('${SERVER_ID}', '${SERVER_IP}', '${SERVER_REGION}')
ON CONFLICT (server_id) DO UPDATE SET ip = EXCLUDED.ip;
EOF

echo "Server $SERVER_ID registered with IP $SERVER_IP"