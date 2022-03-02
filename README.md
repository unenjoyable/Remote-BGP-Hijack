# Remote-BGP-Hijack

Remote-BGP-Hijack is a Python script for hijacking bgp servers.

## Installation

first download pip2 using 
```bash
wget https://bootstrap.pypa.io/get-pip.py
python2 get-pip.py
```
## Usage

Edit the script and change line 22 and 30 where it says 'change to ip you want to redirect the traffic to'

To run the script
```
python2 bgp.py (ip)
```
## Scaning ranges

```
zmap (ip)/24 -p 179
```

