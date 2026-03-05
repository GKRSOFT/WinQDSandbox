## WinQD Sandbox: Windows in Qemu on Docker Sandbox

### WinQD Sandbox is a malware sandbox for CAPEv2.
A sandbox is used to execute malicious files in an isolated environment
whilst instrumenting their dynamic behaviour and collecting forensic artefacts.

### Installation
WinQD Sandbox files:
* Copy the winqd.py file to the /opt/CAPEv2/modules/
* Copy the winqd.conf file to the /opt/CAPEv2/conf/

### Configuration
Edit file /opt/CAPEv2/conf/cuckoo.conf
* Change machinery to winqd

Edit file /opt/CAPEv2/lib/cuckoo/core/routing.conf
* Change internet to none

Update as needed /opt/CAPEv2/conf/winqd.conf
* Update / add an additional WinQD Sandbox

Edit file /opt/CAPEv2/lib/cuckoo/common/constants.py
* Change CUCKOO_GUEST_PORT to 8006

Edit file /opt/CAPEv2/lib/cuckoo/core/guest.py
* insert line 261: self.do_run = False
* Change line 271: r = self.get("/info", do_raise=False)
* Change line 424: status = self.get("/status2", timeout=5).json()


#### Special note about config parsing frameworks:
* Due to the nature of malware, since it changes constantly when any new version is released, something might become broken!
* We suggest using CAPE's framework 
