# VULN: command-injection
# Fixture: OS command injection in Python

import os
import subprocess


def ping_host(host):
    # Unsafe: os.system with concatenated user input
    os.system("ping " + host)


def run_command(cmd):
    # Unsafe: shell=True with user-controlled command
    subprocess.run(cmd, shell=True)
