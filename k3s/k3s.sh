#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
BROWN='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

helpFunction()
{
   echo ""
   echo "Usage: $0
         -n <k3s node ip>
         -h help
	 "
   exit 1 # Exit script after printing help
}

if [ $# -eq 0  ]; then
     helpFunction
    exit 1
fi


while getopts n:h flag
do
    case "${flag}" in
        n) nodeip=${OPTARG};;
        h) helpFunction ;; # Print helpFunction in case parameter is non-existent
    esac
done

echo -e "${BROWN}"
echo "K3S Node IP: $nodeip";
echo -e "${NC}"

interface=$(ip addr show  | grep $nodeip | sed  -E "s%^.*\s(\w*)$%\1%")

echo "Interface: $interface";

#STEP 1  - install k3s

export INSTALL_K3S_SYMLINK=force

echo "===================================="
echo -e "${RED}STEP 1 - install k3s${NC}"
echo "===================================="

echo -e "${BLUE}"
curl -sfL https://get.k3s.io | sh -s - --disable=traefik --flannel-backend=none --node-ip=$nodeip
echo -e "${NC}"

#check if k3s.service is active

systemctl start k3s
ok=0
until [ $ok -eq 1 ]
do
    sleep 1
	echo -e "${BLUE}"
	systemctl is-active k3s.service

        if [ $? -eq 0 ]
        then
	  echo -e "${NC}"
	  ok=1
	  echo -e "${GREEN}"
          echo "K3S  is up" >&2
	  echo -e "${NC}"
        else
          echo -e "${RED}Wait K3S to be up${NC}" >&2
	  ok=0
        fi

done

#STEP 2 - deploy cilium

# set cilium device and K3S API server IP
sed "s/devices: .*/devices: \"$interface\"/; s/K3S-HOST/$nodeip/g;" cilium.yaml > cilium-$nodeip.yaml

echo "===================================="
echo -e "${RED}STEP 2 - deploy cilium${NC}"
echo "===================================="

kubectl apply -f cilium-$nodeip.yaml

ok=0

until [ $ok -eq 1 ]
do
    sleep 10

    for node in $(kubectl  get no  | awk '{print $1;}' | grep -v 'NAME')

    do
        CA=$(kubectl get -l k8s-app=cilium pods -n kube-system --field-selector spec.nodeName=$node -o jsonpath='{.items[0].metadata.name}')

	echo -e "${BLUE}"
    	kubectl exec -it $CA -n kube-system -- cilium status 2>&1>>/dev/null

        if [ $? -eq 0 ]
        then
	  echo -e "${NC}"
	  ok=1
	  echo -e "${GREEN}"
          echo "cilium agent is up" >&2
          echo " " >&2
	  echo -e "${NC}"
          #configure cilium vxlan to BIGIP tunnel
          #tunnel encrypt key
	  echo -e "${NC}"
	  echo -e "${GREEN}"
          kubectl exec -it $CA -n kube-system -- cilium bpf ipcache list
	  echo -e "${NC}"
        else
          echo -e "${RED}Wait for cilium agent to be up${NC}" >&2
	  ok=0
        fi


    done

done

