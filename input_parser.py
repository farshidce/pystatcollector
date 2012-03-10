import getopt
import re
import logger
import ConfigParser
import os

#class to parse the inputs either from command line or from a ini file
#command line supports a subset of
# configuration
# which tests
# ideally should accept a regular expression


class TestInputSingleton():
    input = None


class TestInput(object):

    def __init__(self):
        self.servers = []
        self.moxis = []
        self.clusters = {}
        self.membase_settings = None
        self.test_params = {}
        #servers , each server can have u,p,port,directory

    def param(self, name, default_value):
        if name in self.test_params:
            return TestInput._parse_param(self.test_params[name])
        else:
            return default_value

    @staticmethod
    def _parse_param(value):
        try:
            return int(value)
        except ValueError:
            try:
                return float(value)
            except ValueError:
                return value


class TestInputServer(object):
    def __init__(self):
        self.ip = ''
        self.ssh_username = ''
        self.ssh_password = ''
        self.ssh_key = ''
        self.rest_username = ''
        self.rest_password = ''
        self.port = ''
        self.cli_path = ''
        self.data_path = ''

    def __str__(self):
        ip_str = "ip:{0}".format(self.ip)
        ssh_username_str = "ssh_username:{0}".format(self.ssh_username)
        return "{0} {1}".format(ip_str, ssh_username_str)

    def __repr__(self):
        ip_str = "ip:{0}".format(self.ip)
        ssh_username_str = "ssh_username:{0}".format(self.ssh_username)
        return "{0} {1}".format(ip_str, ssh_username_str)


class TestInputMembaseSetting(object):

    def __init__(self):
        self.rest_username = ''
        self.rest_password = ''


class TestInputBuild(object):
    def __init__(self):
        self.version = ''
        self.url = ''


# we parse this and then pass it on to all the test case
class TestInputParser():

    @staticmethod
    def parse_from_file(file):
        servers = []
        ips = []
        input = TestInput()
        config = ConfigParser.ConfigParser()
        config.read(file)
        sections = config.sections()
        global_properties = {}
        count = 0
        start = 0
        end = 0
        cluster_ips = []
        clusters = {}
        moxis = []
        moxi_ips = []
        client_ips = []
        for section in sections:
            result = re.search('^cluster', section)
            if section == 'servers':
                ips = TestInputParser.get_server_ips(config, section)
            elif section == 'moxis':
                moxi_ips = TestInputParser.get_server_ips(config, section)
            elif section == 'clients':
                client_ips = TestInputParser.get_server_ips(config, section)
            elif section == 'membase':
                input.membase_settings = TestInputParser.get_membase_settings(config, section)
            elif  section == 'global':
                #get global stuff and override for those unset
                for option in config.options(section):
                    global_properties[option] = config.get(section, option)
            elif result is not None:
                cluster_list = TestInputParser.get_server_ips(config, section)
                cluster_ips.extend(cluster_list)
                clusters[count] = len(cluster_list)
                count += 1

        # Setup 'cluster#' tag as dict
        # input.clusters -> {0: [ip:10.1.6.210 ssh_username:root, ip:10.1.6.211 ssh_username:root]}
        for cluster_ip in cluster_ips:
            servers.append(TestInputParser.get_server(cluster_ip, config))
        servers = TestInputParser.get_server_options(servers, input.membase_settings, global_properties)
        for key, value in clusters.items():
            end += value
            input.clusters[key] = servers[start:end]
            start = value

        # Setting up 'servers' tag
        servers = []
        for ip in ips:
            servers.append(TestInputParser.get_server(ip, config))
        input.servers = TestInputParser.get_server_options(servers, input.membase_settings, global_properties)

        # Setting up 'moxis' tag
        moxis = []
        for moxi_ip in moxi_ips:
            moxis.append(TestInputParser.get_server(moxi_ip, config))
        input.moxis = TestInputParser.get_server_options(moxis, input.membase_settings, global_properties)

        # Setting up 'clients' tag
        input.clients = client_ips

        return input

    @staticmethod
    def get_server_options(servers, membase_settings, global_properties):
        for server in servers:
                if server.ssh_username == '' and 'username' in global_properties:
                    server.ssh_username = global_properties['username']
                if server.ssh_password == '' and 'password' in global_properties:
                    server.ssh_password = global_properties['password']
                if server.ssh_key == '' and 'ssh_key' in global_properties:
                    server.ssh_key = os.path.expanduser(global_properties['ssh_key'])
                if not server.port and 'port' in global_properties:
                    server.port = global_properties['port']
                if server.cli_path == '' and 'cli' in global_properties:
                    server.cli_path = global_properties['cli']
                if server.rest_username == '' and membase_settings.rest_username != '':
                    server.rest_username = membase_settings.rest_username
                if server.rest_password == '' and membase_settings.rest_password != '':
                    server.rest_password = membase_settings.rest_password
                if server.data_path == '' and 'data_path' in global_properties:
                    server.data_path = global_properties['data_path']
        return servers

    @staticmethod
    def get_server_ips(config, section):
        ips = []
        options = config.options(section)
        for option in options:
            ips.append(config.get(section, option))
        return ips

    @staticmethod
    def get_server(ip, config):
        server = TestInputServer()
        server.ip = ip
        for section in config.sections():
            if section == ip:
                options = config.options(section)
                for option in options:
                    if option == 'username':
                        server.ssh_username = config.get(section, option)
                    if option == 'password':
                        server.ssh_password = config.get(section, option)
                    if option == 'cli':
                        server.cli_path = config.get(section, option)
                    if option == 'ssh_key':
                        server.ssh_key = config.get(section, option)
                    if option == 'port':
                        server.port = config.get(section, option)
                    if option == 'ip':
                        server.ip = config.get(section, option)
                break
                #get username
                #get password
                #get port
                #get cli_path
                #get key
        return server

    @staticmethod
    def get_membase_build(config, section):
        membase_build = TestInputBuild()
        for option in config.options(section):
            if option == 'version':
                pass
            if option == 'url':
                pass
        return membase_build

    @staticmethod
    def get_membase_settings(config, section):
        membase_settings = TestInputMembaseSetting()
        for option in config.options(section):
            if option == 'rest_username':
                membase_settings.rest_username = config.get(section, option)
            if option == 'rest_password':
                membase_settings.rest_password = config.get(section, option)
        return membase_settings

    @staticmethod
    def parse_from_command_line(argv):

        input = TestInput()

        try:
            # -f : won't be parse here anynore
            # -s will have comma separated list of servers
            # -t : wont be parsed here anymore
            # -v : version
            # -u : url
            # -b : will have the path to cli
            # -k : key file
            # -p : for smtp ( taken care of by jenkins)
            # -o : taken care of by jenkins
            servers = []
            membase_setting = None
            (opts, args) = getopt.getopt(argv[1:], 'h:t:c:i:p:', [])
            #first let's loop over and find out if user has asked for help
            need_help = False
            for option, argument in opts:
                if option == "-h":
                    print 'usage...'
                    need_help = True
                    break
            if need_help:
                return
            #first let's populate the server list and the version number
            for option, argument in opts:
                if option == "-s":
                    #handle server list
                    servers = TestInputParser.handle_command_line_s(argument)
                elif option == "-u" or option == "-v":
                    input_build = TestInputParser.handle_command_line_u_or_v(option, argument)

            #now we can override the username pass and cli_path info
            for option, argument in opts:
                if option == "-k":
                    #handle server list
                    for server in servers:
                        if server.ssh_key == '':
                            server.ssh_key = argument
                elif option == "--username":
                    #handle server list
                    for server in servers:
                        if server.ssh_username == '':
                            server.ssh_username = argument
                elif option == "--password":
                    #handle server list
                    for server in servers:
                        if server.ssh_password == '':
                            server.ssh_password = argument
                elif option == "-b":
                    #handle server list
                    for server in servers:
                        if server.cli_path == '':
                            server.cli_path = argument
            # loop over stuff once again and set the default
            # value
            for server in servers:
                if server.ssh_username == '':
                    server.ssh_username = 'root'
                if server.ssh_password == '':
                    server.ssh_password = 'northscale!23'
                if server.cli_path == '':
                    server.cli_path = '/opt/membase/bin/'
                if not server.port:
                    server.port = 8091
            input.servers = servers
            input.membase_settings = membase_setting
            return input
        except Exception:
            log = logger.Logger.get_logger()
            log.error("unable to parse input arguments")
            raise
