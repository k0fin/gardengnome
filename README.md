# GardenGnome

GNOME process memory cleartext password disclosure

## about
  * GardenGnome is a Python2 script used to dump cleartext passwords from GNOME Display Manager process memory.
    When a user is logged in to their desktop using GNOME Display Manager, the cleartext string value of the user's
    password can be found within the memory space of 3 different GNOME-related processes. In order to dump the root
    user's password, the script must be ran as root or a normal user who has or can manage to gain the privileges to run Python2 as a root user.

  * Additionally, any users who lock the screen of their desktop have cached their password in the affected regions of memory. Therefore,
    if a user has the privileges to dump process memory for these other "locked-screen" users, the passwords for these users can be
    disclosed as well.
## install
  * pip install -r requirements.txt

## usage
  * python2 gardengnome.py --attack
  * ./gardengnome.py --attack

## todo
  * Implement or make use of more native or built-in Python code to reduce the number of Python module dependencies
    needed to run the attack locally on a victim Linux machine.

  * Implement local authentication check to bruteforce password from memory string list without the need
    to read /etc/shadow.

  * Detect if a user session is running with a locked screen while the attacker is logged in.
    This will allow GardenGnome to detect which specific user accounts to target, and will
    allow a root user or normal user with equal rights / privileges to harvest all passwords
    for locked user accounts.

  * Implement native / integrated kill chain.

!! IMPORTANT: README.md is not complete. More information coming soon.
