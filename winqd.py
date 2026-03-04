# Copyright (C) 2012-2014 The MITRE Corporation.
# Copyright (C) 2015-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import socket
import struct
import sys
from time import sleep

import requests

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT
from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooMachineError

log = logging.getLogger(__name__)
managerType = Config("winqd").winqd.type


class Winqd(Machinery):
    """Manage winqd sandboxes."""

    module_name = "winqd"

    # Winqd machine states.
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"

    headers = {}

    def _initialize_check(self):
        """Ensure that credentials have been entered into the config file.
        @raise CuckooCriticalError: if no credentials were provided or if
            one or more winqd machines are offline.
        """

        for machine in self.machines():
            status = self._status(machine.label)
            #if status == self.STOPPED:
                #self.wake_on_lan(machine.label)
            if status == self.ERROR:
                raise CuckooMachineError(
                    "Unknown error occurred trying to obtain the status of "
                    f"winqd machine {machine.label}. Please turn it on "
                    " and check the Cuckoo Agent"
                )

    def _get_machine(self, label):
        """Retrieve all machine info given a machine's name.
        @param label: machine name.
        @return: machine dictionary (id, ip, platform, ...).
        @raises CuckooMachineError: if no machine is available with the given label.
        """
        for m in self.machines():
            if label == m.label:
                return m

        raise CuckooMachineError(f"No machine with label: {label}")


    def start(self, label):
        """Start a winqd machine.
        @param label: winqd machine name.
        @param task: task object.
        @raise CuckooMachineError: if unable to start.
        """
        # Check to ensure a given machine is running
        log.debug("Checking if machine %s is running", label)
        status = self._status(label)
        if status == self.RUNNING:
            log.debug("Machine already running: %s", label)
        elif status == self.STOPPED:
            self._wait_status(label, self.RUNNING)
        else:
            raise CuckooMachineError(f"Error occurred while starting: {label} (STATUS={status})")

    def stop(self, label):
        """Stop a physical machine.
        @param label: physical machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        taskID_Deploy = 0
        hostID = 0

        if self._status(label) == self.RUNNING:
            log.debug("Rebooting machine: %s", label)
            machine = self._get_machine(label)

        try:
            if managerType == "pure":
                url = f"http://{machine.ip}:{CUCKOO_GUEST_PORT}"
                r = requests.get(f"{url}/revirtVM")
                print(r.text)
        except Exception:
            # The reboot will start immediately which may kill our socket so we just ignore this exception
            log.debug("Socket killed from analysis machine due to reboot")


        # After the restore operation is done we are waiting until it is up again and we can connect to the agent
        url = f"http://{machine.ip}:{CUCKOO_GUEST_PORT}"

        connection_succesful = False

        while not connection_succesful:
            try:
                r = requests.get(f"{url}/status2")
                print(r.text)
                connection_succesful = True
            except Exception:
                log.debug("Machine not reachable yet after reset")
                sleep(3)

            
    def _list(self):
        """List winqd machines installed.
        @return: winqd machine names list.
        """
        return [machine.label for machine in self.machines() if self._status(machine.label) == self.RUNNING]

    def _status(self, label):
        """Get current status of a winqd machine.
        @param label: winqd machine name.
        @return: status string.
        """
        # For winqd machines, the agent can either be contacted or not.
        # However, there is some information to be garnered from potential
        # exceptions.
        log.debug("Getting status for machine: %s", label)
        machine = self._get_machine(label)

        # The status is only used to determine whether the Guest is running
        # or whether it is in a stopped status, therefore the timeout can most
        # likely be fairly arbitrary. TODO This is a temporary fix as it is
        # not compatible with the new Cuckoo Agent, but it will have to do.
        url = f"http://{machine.ip}:{CUCKOO_GUEST_PORT}"

        try:
            r = requests.get(f"{url}/status2")
            print(r.text)
            return self.RUNNING
        except Exception:
            return self.STOPPED


    def create_magic_packet(self, macaddress):
        if len(macaddress) == 12:
            pass
        elif len(macaddress) == 17:
            sep = macaddress[2]
            macaddress = macaddress.replace(sep, "")
        else:
            log.debug("Incorrect MAC address format: %s", macaddress)
            return False

        # Pad the synchronization stream
        data = b"FFFFFFFFFFFF" + (macaddress * 16).encode()
        send_data = b""

        # Split up the hex values in pack
        for i in range(0, len(data), 2):
            send_data += struct.pack(b"B", int(data[i : i + 2], 16))
        return send_data
