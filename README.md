# Automating evil twin attacks

## Presteps

* Have a wifi card (we used an Alfa)
* Be in kali
* `apt-get install hostapd` 

## Running the software

`python3 main.py`

Providing a password will trigger the creation of a hostapd conf file with the necesssary info to clone a WPA2 access point

Skipping this step will trigger the creation of an unencrypted clone

Both will then deauth all existing clients on the access point, and continue deauthing them until you kill the script. Hopefully they reconnect to you.

Tail your victims with `tail -f /var/log/dnsmasq.log`
