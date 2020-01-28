#!/bin/bash

#uses arg of ip-range/netmask to create task for each ip/host
echo "running live hosts map for" $1
nmap -n --open -p21,22,23,25,53,80,135,139,445,443,3389,4635,4640,3040,8080,5800,5900,9443 $1 -oX - | xmlstarlet sel -t -m '//address[@addrtype="ipv4"]' -v '@addr' -n >> livehosts.txt

#clean up duplication from nmap, rarely happens but can break stuff
sort livehosts.txt | uniq -u > livehosts-loaded.txt
rm livehosts.txt


echo "building tasks in openvas"
#Could do this inside of python script with asyncio, but xargs works for now
cat livehosts-loaded.txt | xargs -L 1 -I {} ./LoadTurret.py -i {} -n "{}" -c "test comment"
rm livehosts-loaded.txt


echo "firing tasks"
#cleaner to run this in shell, rather than in fireturret python, leaves task record for debugs and manual execution too
#will create monolithic python solution for this later on after POC review
omp --get-tasks | sed 's/\s.*$//' > task-list.txt
cat task-list.txt | xargs -L 1 -I {} omp -S {}
rm task-list.txt

###notes and junk###

#good for grabbing hostname from nmap xml out, not needed right now
#nmap -sn $1 -oX - | xmlstarlet sel -t -m "//host/status[@state='up']/.." -v "address[@addrtype='ipv4']/@addr" -o " " -v "hostnames/hostname/@name" -n >> livehosts.txt
