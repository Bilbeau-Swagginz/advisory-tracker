# advisory-tracker

Small Python tool that checks packages installed on Arch-based Linux machines against public security advisories.

#Status

WORK IN PROGRESS - Currently list patches installed via pacman -Q. Next step is advisory matching. 

#Usage

python tracker.py

#Roadmap
- Fetch advisory data from Arch Security tracker
- Match installed package versions against known advisories
- Sort results by CVE score
- Notifications and scheduled runs
- 
