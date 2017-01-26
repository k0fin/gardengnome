# gardengnome

GNOME process memory cleartext password disclosure

## about
  * gardengnome.py must be ran as root from the working directory of the script.

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
