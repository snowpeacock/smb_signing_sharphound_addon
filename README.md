# SMB signing Sharphound addon
 Little python scripts to check SMB signing requirements on remote SMBv3 hosts with impacket. Adds SMB_signing attribute in sharphound json. 
```
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
python3 sharphound_addon.py YYYYMMDDXXXXXX_computers.json
```
or just
```
python3 check_signing.py targets
```
> [!TIP]
> Make an exe with `pyinstaller --onefile sharphound_addon.py` on a windows host. Will be flagged.
