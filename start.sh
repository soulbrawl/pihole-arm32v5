#!/usr/bin/env bash

sudo service pihole-FTL start > /dev/null 2>&1
sudo service lighttpd start > /dev/null 2>&1
sudo service ssh start > /dev/null 2>&1
sleep infinity