#! /usr/bin/env python

# author: phchoi
# neutron-port-scan-tool.py
# TODO:
# - better comment and tidy up the code
# - better error handling
# - lock mechanism to avoid duplicate run?


import os
import re
import sys
import time
import fnmatch
import logging
import paramiko
import argparse
import threading

from neutronclient.v2_0 import client as neutron_client

# noinspection PyPep8Naming
from keystoneclient.v2_0 import client as keystone_client

# this is the class that do the neutron port listing.
# the port list will be first saved under _base_log_dir.
# Depending on the DHCP/L3 namespace the port is attached to,
# the port will then be listed under the corresponding
# ping_from_(qdhcp|l3)_on_$network_node.list and distributed to
# different target network nodes.


class PortList(object):
    """PortList."""

    # initialize the class variables
    def __init__(self, **args):
        """Init PortList."""

        self._keystone = keystone_client.Client(**args)

        neutron_endpoint = self._keystone.service_catalog.url_for(
                           service_type='network',
                           endpoint_type='internalURL'
                           )
        self._neutron = neutron_client.Client(
                        endpoint_url=neutron_endpoint,
                        token=self._keystone.auth_token
                        )

        self._network_id = args.get('network')
        self._router_id = args.get('router')
        self._network_agent = args.get('network_agent')
        self._base_log_dir = args.get('logdir')
        self._start_time = time.time()
        self._logger = args.get('log')

    # neutron port list
    def get_neutron_port_list(self):
        """Get Neutron Ports (neutron port-list)"""

        if self._network_id is None:
            raw_ports = self._neutron.list_ports(status='ACTIVE')
        else:
            raw_ports = self._neutron.list_ports(network_id=self._network_id, status=ACTIVE)

        self._logger.info('Finished neutron port-list, %s active ports found'
                          % (len(raw_ports['ports'])))

        return raw_ports

    # this is to filter the ports based on type of port
    def categorize_port(self, raw_ports):
        instance_ports = []
        router_ports = []
        dhcp_agent_ports = []
        other_ports = []
        all_ports = {}
        for port in raw_ports['ports']:
            massaged_port = self.massage_port(port)
            # instance port usually named as "compute:None" or "compute:$AZ"
            if port['device_owner'].startswith('compute:'):
                instance_ports.append(massaged_port)
            elif port['device_owner'] in (
                            'network:router_gateway',
                            'network:router_interface'):
                if self._network_agent is not None:
                    if port['binding:host_id'] == self._network_agent:
                        router_ports.append(massaged_port)
                else:
                    router_ports.append(massaged_port)
            elif port['device_owner'] in ('network:dhcp'):
                if self._network_agent is not None:
                    if port['binding:host_id'] == self._network_agent:
                        dhcp_agent_ports.append(massaged_port)
                else:
                    dhcp_agent_ports.append(massaged_port)
            else:
                other_ports.append(massaged_port)

        # encapsulate all ports to a dict
        for item in ['instance_ports', 'router_ports',
                     'dhcp_agent_ports', 'other_ports']:
            all_ports[item] = eval(item)

        self._logger.info('Finished categorizing ports. '
                          'Found %s instances ports, %s router ports, '
                          '%s dhcp agent ports, %s other ports' %
                          (len(all_ports['instance_ports']),
                           len(all_ports['router_ports']),
                           len(all_ports['dhcp_agent_ports']),
                           len(all_ports['other_ports'])
                           )
                          )

        return all_ports

    # this method will message the data structure of a port to a
    # more managible format
    def massage_port(self, port):
        massaged_port = {}
        for key in ('id', 'device_owner', 'network_id', 'tenant_id',
                    'device_id', 'mac_address'):
            massaged_port[key] = port[key]
        massaged_port['subnet_id'] = port['fixed_ips'][0]['subnet_id']
        massaged_port['ip_address'] = port['fixed_ips'][0]['ip_address']
        massaged_port['on_node'] = port['binding:host_id']
        if port['device_owner'].startswith('compute:'):
            massaged_port['tap'] = "tap" + port['id'][0:11]
        elif port['device_owner'] == 'network:dhcp':
            massaged_port['tap'] = "tap" + port['id'][0:11]
        elif port['device_owner'] == 'network:router_interface':
            massaged_port['tap'] = "qr-" + port['id'][0:11]
        elif port['device_owner'] == 'network:router_gateway':
            massaged_port['tap'] = "qg-" + port['id'][0:11]
        return massaged_port

    # setup log directory and files
    def setup_log(self):
        if not os.path.exists(self._base_log_dir):
            os.makedirs(self._base_log_dir)

        # this is to clean up the previously saved port lists (usually suffix with .list)
        # some of these port list files will be scp to network nodes as a list to be ping
        # the clean up is to make sure all ports to be scanned are valid ports
        log = []
        for file in os.listdir(self._base_log_dir):
            #if re.match(r'.*\.list', file):
            if file.endswith('.list'):
                log.append(file)

        # create log file so output of the ping can be written
        for item in log:
            log_path = self._base_log_dir + '/' + item
            open(log_path, 'w').close()

    # from categorized dhcp_agent and instance ports,
    # build up a list of compute ports to ping from the corresponding namespace
    def generate_port_ping_list_from_dhcp_agent(self,
                                                instance_ports,
                                                dhcp_agent_ports):
        consolidated_ports = {}
        instance_ports_count = 0

        # define a port list files that contain all the compute ports
        instance_port_list = (self._base_log_dir + '/' +
                             'all_instance_port_connected_to_dhcp.list')

        # loop through all the compute ports
        # if the network_id of the port match with the network_id of the dhcp
        # agent port encapsulate the port info into 'port_to_ping' and append
        # it to a list of ports to ping
        file_handle = open(instance_port_list, 'a')
        for port in instance_ports:
            for dhcp_port in dhcp_agent_ports:
                if port['network_id'] == dhcp_port['network_id']:
                    instance_ports_count += 1
                    file_handle.write(str(port)+'\n')
                    port_to_ping = {}
                    for key in ('id', 'network_id', 'subnet_id', 'ip_address'):
                        port_to_ping[key] = port[key]
                    port_to_ping['tap'] = dhcp_port['tap']
                    port_to_ping['instance_id'] = port['device_id']
                    agent = dhcp_port['on_node']
                    consolidated_ports.setdefault(agent, [])
                    consolidated_ports[agent].append(port_to_ping)
        file_handle.close()

        # key in consolidated_ports dict is the agent name
        # under each key or agent,
        # there is a list of compute ports that will be ping
        #
        # ping_from_qdhcp_ns_in_ file contain compute ports to be ping
        # network_id is the network uuid of the dhcp namespace
        # tap is the tap interface that under dhcp namepsace,
        # arping will use the tap interface to ping
        for key in consolidated_ports:
            ping_test_file = (self._base_log_dir + '/' +
                              'ping_from_qdhcp_ns_in_' + key + '.list')
            #f = open(ping_test_file, 'w').close()
            f = open(ping_test_file, 'a')
            line = ("#port_id network_id ping_through_tap "
                    "ip_address instance_id subnet_id")
            f.write(line + '\n')
            for port in consolidated_ports[key]:
                line = "%s %s %s %s %s %s" % (
                       port['id'], port['network_id'], port['tap'],
                       port['ip_address'], port['instance_id'],
                       port['subnet_id'])
                f.write(line + '\n')
            f.close()
        self._logger.info('Found %s instance ports to ping from all '
                          'DHCP namespace' % (instance_ports_count)
                          )
        return consolidated_ports

    # from categorized l3_agent and instance ports
    # build up a list of compute ports to ping
    # from the corresponding namespace
    def generate_port_ping_list_from_l3_agent(self,
                                              instance_ports,
                                              router_ports):
        # TODO: ping from L3 to north using qg interface
        consolidated_ports = {}
        instance_ports_count = 0

        # define a port list files that contain all the compute ports
        # that connect to a l3 router
        instance_port_log = (self._base_log_dir + '/' +
                             'all_instance_port_connected_to_l3.list')

        def test_if_port_is_connected_to_l3(instance_port, l3_port):
            if l3_port['device_owner'] == 'network:router_interface':
                if instance_port['subnet_id'] == l3_port['subnet_id']:
                    return True

        def format_l3_connected_port(instance_port, l3_port):
            port_to_ping = {}
            port_to_ping['id'] = port['id']
            port_to_ping['network_id'] = port['network_id']
            port_to_ping['subnet_id'] = port['subnet_id']
            port_to_ping['router_id'] = l3_port['device_id']
            port_to_ping['tap'] = l3_port['tap']
            port_to_ping['ip_address'] = port['ip_address']
            port_to_ping['instance_id'] = port['device_id']
            return port_to_ping

        # loop through all the compute ports
        # if the network_id of the port match with the network_id
        # of the l3 agent port.
        # encapsulate the port info into 'port_to_ping' and append
        # it to a list of ports to ping
        for port in instance_ports:
            f = open(instance_port_log, 'a')
            f.write(str(port)+'\n')
            f.close()
            # - if a router is specified in the command line as ping source
            #   self._router_id will be defined and only ports that are connected
            #   to self._router_id will be added to the consolidated_port list
            # - if self._router_id is not specified (None), all routers' connected
            #   will be added to the consolidated_port list
            for l3_port in router_ports:
                if self._router_id is None or self._router_id == l3_port['device_id']:
                    if test_if_port_is_connected_to_l3(port, l3_port):
                        port_to_ping = format_l3_connected_port(port, l3_port)
                        instance_ports_count += 1
                        agent = l3_port['on_node']
                        # initialize consolidated_ports[agent] if it is not there
                        consolidated_ports.setdefault(agent, [])
                        consolidated_ports[agent].append(port_to_ping)

        # key in consolidated_ports dict is the agent name
        # under each key/agent, there is a list of compute ports to be ping
        # ping_from_qrouter_ns_in_ file contain compute ports to be ping
        # router_id is the router uuid  and it be used as the namespace
        # tap is the tap interface that under l3 namepsace,
        # arping will use the tap interface to ping
        for key in consolidated_ports:
            ping_test_file = (self._base_log_dir + '/' +
                              'ping_from_qrouter_ns_in_' + key + '.list')
            f = open(ping_test_file, 'a')
            line = ("#port_id router_id ping_through_tap ip_address " +
                    "instance_id subnet_id network_id")
            f.write(line + '\n')
            for port in consolidated_ports[key]:
                line = ' '.join([
                       port['id'], port['router_id'], port['tap'],
                       port['ip_address'], port['instance_id'],
                       port['subnet_id'], port['network_id']
                       ])
                f.write(line + '\n')
            f.close()

        self._logger.info('Found %s instance ports to ping from all '
                          'L3 namespace' % (instance_ports_count)
                          )
        return consolidated_ports

    def start(self):
        self_start_time = time.time()
        self.setup_log()
        self._logger.info('Start doing neutron port-list')
        raw_ports = self.get_neutron_port_list()
        all_ports = self.categorize_port(raw_ports)
        if self._router_id is None:
            self.generate_port_ping_list_from_dhcp_agent(
                                           all_ports['instance_ports'],
                                           all_ports['dhcp_agent_ports']
                                           )
        self.generate_port_ping_list_from_l3_agent(
                                       all_ports['instance_ports'],
                                       all_ports['router_ports']
                                       )
        # this save all the qr (router_interface) and
        # qg (router_gateway) ports to the text file
        f = open(self._base_log_dir + '/' + 'router_port.list', 'a')
        for port in all_ports['router_ports']:
            f.write(str(port)+'\n')
        f.close()

        elapsed = time.time() - self._start_time
        self._logger.info('Finished port list in %s secs' % (elapsed))


# this is the class that actually handle the port scan
class PortScan(object):
    """PortScan."""

    # initialize all the class variables
    def __init__(self, **args):
        """Init PortScan."""

        self._base_log_dir = args.pop('logdir')
        self._ping_script_path = self._base_log_dir + '/' + 'portping.py'
        self._ping_list = []
        self._ssh_target = {}
        self._all_ssh_output = []
        self._start_time = time.time()
        self._logger = args.pop('log')

        self._ssh = paramiko.SSHClient()

    # it read the ping list from self._base_log_dir
    # and based on the name of the list, it will be added to the
    # self._ssh_target dict for further operation
    def read_ping_list(self):
        self._logger.info('Start loading the port list')
        for file in os.listdir(self._base_log_dir):
            if fnmatch.fnmatch(file, 'ping_from_*_ns_in_*.list'):
                self._ping_list.append(file)
                host = re.sub(r'ping_from_(qrouter|qdhcp)_ns_in_',
                              '', file).rstrip('.list')
                self._ssh_target.setdefault(host, [])
                self._ssh_target[host].append(file)

    # looping over self._ssh_target and scp the files to remote
    # dhcp or l3 agent node
    def scp_ping_list_to_remote(self):
        self._logger.info('Start copying port list to remote network nodes')
        for key in self._ssh_target:
            host = key
            self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._ssh.connect(host, username='root',
                              key_filename='/root/.ssh/id_rsa')
            for file in self._ssh_target[key]:
                sftp = self._ssh.open_sftp()
                file_path = self._base_log_dir + '/' + file
                try:
                    sftp.chdir(self._base_log_dir)
                except IOError:
                    sftp.mkdir(self._base_log_dir, 0755)
                sftp.chdir(self._base_log_dir)
                sftp.put(file_path, file_path)
                sftp.put(self._ping_script_path, self._ping_script_path)
                sftp.chmod(self._ping_script_path, 0755)

    # ssh to the remote node and execute the script to start the ping
    def ssh_port_scan(self, host, port_lists):
        self._logger.info('Start ssh %s to scan ports. '
                          'Could take a while, please wait' % (host))
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(
                             paramiko.AutoAddPolicy())
        ssh.connect(host, username='root',
                    key_filename='/root/.ssh/id_rsa')
        for file in port_lists:
            command = (self._ping_script_path + ' --file ' +
                       self._base_log_dir + '/' + file)
            stdin, stdout, stderr = ssh.exec_command(command)
            # this save the ping result for furter processsing
            for i in stdout.readlines():
                self._all_ssh_output.append(host + ' ' + i.rstrip('\n'))

    # ssh to the remote node and execute the script to start the ping
    def pop_queue(self, key):
        port_list = None

        if self._ssh_target[key]:
            port_list = self._ssh_target[key].pop()

        return port_list

    # ssh to the remote node and execute the script to start the ping
    def dequeue(self, key):
        port_lists = []
        while True:
            port_list = self.pop_queue(key)
            if port_list:
                port_lists.append(port_list)
            else:
                break
        return port_lists

    # this process the result from the ping and print some stats
    def print_stats_after_ping(self):
        elapsed = time.time() - self._start_time
        self._all_ssh_output.sort()
        stats = {}
        for line in self._all_ssh_output:
            self._logger.info("%s" % (line))
            host = line.split()[0]
            stats.setdefault(host, {})
            stats[host].setdefault('total', 0)
            stats[host].setdefault('timeout', 0)
            stats[host].setdefault('reachable', 0)
            stats[host]['total'] += 1
            if re.match(r".*timeout", line):
                stats[host]['timeout'] += 1
            elif re.match(r".*reachable", line):
                stats[host]['reachable'] += 1
        self._logger.info('Port scan finished in %s secs' % (elapsed))
        total_ping = len(self._all_ssh_output)
        timeout_count = len(filter(lambda x: 'timeout' in x,
                                   self._all_ssh_output))
        reachable_count = len(filter(lambda x: 'reachable' in x,
                                     self._all_ssh_output))
        # key is the network agent name, aka hostname
        stats_keylist = stats.keys()
        stats_keylist.sort()
        for key in stats_keylist:
            self._logger.info("Ping statistics from %s: total %s, "
                              "reachable %s, timeout %s " %
                              (key, stats[key]['total'],
                               stats[key]['reachable'],
                               stats[key]['timeout']))
        self._logger.info("Total ping attempts: %s" % (total_ping))
        self._logger.info("Total ping reachable: %s" % (reachable_count))
        self._logger.info("Total ping timeout: %s" % (timeout_count))

    # the main routine that start the ping
    # it puts all ssh session under multi-threaded so they can be ran
    # simultaneously.
    def start(self):
        threads = []
        self.read_ping_list()
        self.create_and_copy_ping_script(self._ping_script_path)
        self.scp_ping_list_to_remote()
        for key in self._ssh_target:
            port_lists = self.dequeue(key)
            try:
                thread = threading.Thread(target=self.ssh_port_scan,
                                          args=(key, port_lists))
                thread.start()
                threads.append(thread)
            except (KeyboardInterrupt, SystemExit):
                print '\n! Received keyboard interrupt, quitting threads.\n'

        [t.join() for t in threads]
        self.print_stats_after_ping()

    # create the python script file to actually do the ping
    def create_and_copy_ping_script(self, path):

        script = '''#!/usr/bin/env python

import os
import subprocess
import threading
import argparse

class PortPing(object):
    def __init__(self, **args):

        self._port_list = []
        self._ns_type = ''
        self._thread_count = 4
        self._lock = threading.Lock()
        self._out = []

    def open_ping_list(self, file):
        f = open(file)
        lines = f.read().split('\\n')
        # remove the first line which is the comment line
        del lines[0]
        # take out empty string from the list
        self._port_list = filter(None, lines)
        self._ns_type = file.split('/')[-1].split('_')[2]

    def arping(self, port, ns_type):
        column =  port.split()
        port_id = column[0]
        namespace = ns_type + '-' + column[1]
        tap = column[2]
        ip_address = column[3]
        instance_id = column[4]
        command = "ip netns exec %s /usr/sbin/arping -I %s %s -c 1 -w 2" \
                                              % ( namespace, tap, ip_address)
        output="%s %s %s %s %s" % (port_id, namespace, tap,
                                   ip_address, instance_id)
        if self.arping_cmd(command):
            self._out.append(output + " reachable")
        else:
            self._out.append(output + " timeout")

    def arping_cmd(self, args):
        try:
            returncode = subprocess.check_call(args, shell=True,
                                               stdout=open(os.devnull, 'w'),
                                               stderr=subprocess.STDOUT)
            if returncode == 0:
                return True
            else:
                return False
        except Exception:
            return False

    def pop_queue(self):
        port = None

        self._lock.acquire() # Grab or wait+grab the lock.

        if self._port_list:
            port = self._port_list.pop()

        # Release the lock, so another thread could grab it.
        self._lock.release()

        return port

    def dequeue(self):
        while True:
            port = self.pop_queue()

            if not port:
                return None

            self.arping(port, self._ns_type)
            #self._out.append(result)

    # ping are executed under multi thread as well
    def start(self, file):
        threads = []
        self.open_ping_list(file)
        for i in range(self._thread_count):
            thread = threading.Thread(target=self.dequeue)
            thread.start()
            threads.append(thread)

        [ t.join() for t in threads ]


    def print_out(self):
        for line in self._out:
            print line

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', type=str, action='store')
    args = parser.parse_args()
    if os.path.isfile(args.file):
        file = args.file

    portping = PortPing()
    portping._thread_count=8
    portping.start(file)
    portping.print_out()
'''
    # End of remote port ping script

        text_file = open(path, "w")
        text_file.write(script)
        text_file.close()
        os.chmod(path, 0755)


def setup_logger(log_path):
    logger = logging.getLogger(__name__)
    if log_path is None:
        handler = logging.StreamHandler(sys.stdout)
    else:
        handler = logging.FileHandler(log_path)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


if __name__ == '__main__':
    # ensure environment has necessary items to authenticate
    for key in ['OS_TENANT_NAME', 'OS_USERNAME', 'OS_PASSWORD',
                'OS_AUTH_URL']:
        if key not in os.environ.keys():
            print "Openstack credential missed"
            exit(1)
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--rerun', action='store_true',
                        help="Re-run with previous data, specify--log-dir or "
                              "otherwise will get from default log directory")
    parser.add_argument('-l', '--log-dir', type=str, action='store',
                        default='/tmp/ping_test/',
                        help="Unless specified, default is '/tmp/ping_test/'")
    parser.add_argument('-n', '--network', type=str, action='store',
                        help="Network UUID. Optional, only ping against "
                              "ports connected to particular network")
    parser.add_argument('-a', '--network_agent', type=str, action='store',
                        help="Network node name. Optional, only ping against "
                              "ports connected to particular network node")
    parser.add_argument('-R', '--router', type=str, action='store',
                        help="Router UUID. Optional, only ping against "
                              "ports connected to particular router")
    parser.add_argument('-s', '--log_stdout', action='store_true',
                        default=False, help='Print output to stdout')
    parser.add_argument('-k', '--insecure', action='store_true',
                        default=False, help='allow connections to SSL sites '
                                            'without certs')

    args = parser.parse_args()
    os_args = dict(auth_url=os.environ.get('OS_AUTH_URL'),
                   username=os.environ.get('OS_USERNAME'),
                   tenant_name=os.environ.get('OS_TENANT_NAME'),
                   password=os.environ.get('OS_PASSWORD'),
                   endpoint_type=os.environ.get('OS_ENDPOINT_TYPE',
                                                'publicURL'),
                   insecure=args.insecure,
                   datadir=args.rerun,
                   network_agent=args.network_agent,
                   network=args.network,
                   router=args.router,
                   logdir=args.log_dir)

    if not os_args['logdir'].endswith('/'):
        os_args['logdir'] = args.log_dir + '/'

    if not args.log_stdout:
        # creating individual log for each time is by design.
        # people can easily check back the result of each time without doing
        # any kind of grep
        log_file = time.strftime("ping-result-%Y-%m-%d-%H:%M:%S.log")
        log_path = (os_args['logdir'] + log_file)
        print("Log will be saved under %s , please wait ..." % log_path)
    else:
        log_path = None
    logger = setup_logger(log_path)
    os_args['log'] = logger

    if args.rerun is False:
        port_list = PortList(**os_args)
        port_list.start()
    port_scan = PortScan(**os_args)
    port_scan.start()
