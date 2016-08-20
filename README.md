**gpp**
-----
**Exploitation of Group Policy Preferences**
 
>Author: Darryl Lane  |  Twitter: @darryllane101

>https://github.com/darryllane/gpp

Originally the vulnerability was reported in MS14-025 as 'The vulnerability could allow elevation of
privilege if Active Directory Group Policy preferences are used to distribute passwords across
the domain'. This was patched, however the issue is still exploitable for other preference
options as long as they require authentication to execute.

This script is used to gather the cpassword used in Group Policy Preferences and decrypt it regardless
of the hosting xml file.

Authors: Darryl Lane | Twitter: @darryllane101

**Usage:**
  gpp (-s <server>) (-d <domain>) (-u <username>) (-p <password>)
  gpp --version
  gpp -h

**Example:**

     gpp -s 192.168.1.111 -d dlsec.local -u administrator -p Password123

**Options:**
    
    -d <domain>        Target Domain name.
    -u <username>      A valid domain user account, username.
    -p <password>      A valid domain user account, password.
    -h --help          Show this screen.
    --version          Show version.

**Pip Install Instructions**

Note: To test if pip is already installed execute.

`pip -V`

(1) Mac and Kali users can simply use the following command to download and install `pip`.

`curl https://bootstrap.pypa.io/get-pip.py -o - | python`

**Bluto Install Instructions**

(1) Once `pip` has successfully downloaded and installed, we can install Bluto:

`sudo pip install git+git://github.com/darryllane/gpp`

(2) You should now be able to execute 'bluto' from any working directory in any terminal.
 
`gpp`

**Upgrade Instructions**

(1) The upgrade process is as simple as;

`sudo pip install git+git://github.com/darryllane/gpp --upgrade`

Change/Feature Requests
====
* Mine NETLOG for credentials

Changelog
====
* Version __1.0.0__ (__20/08/2016__):
  * Mines SYSVOL for encrypted passwords and decrypts them.
  * Evidences the data identified and it's location.


