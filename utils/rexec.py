import os
import logging
import ssh

logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG)

class SshExec(object):
    """
    Connects to remote host through given ssh connection and executes
    a preset command(s).
    """
    def __init__(self):
        """
        Create new RmtExec object.
        """
        self.commands = list()
        self.sshClient = None


    def get_ssh_client(self):
        """
        Returns configured client
        :return: SSHClient
        """
        return self.sshClient

    def connect(self, hostname, port=ssh.client.SSH_PORT, username=None, password=None, pkey=None,
                key_filename=None, timeout=None, allow_agent=True):
        """
        Connects using newly created sshClient to ssh server using the following parameters:

        @param hostname: the server to connect to
        @type hostname: str
        @param port: the server port to connect to
        @type port: int
        @param username: the username to authenticate as (defaults to the
            current local username)
        @type username: str
        @param password: a password to use for authentication or for unlocking
            a private key
        @type password: str
        @param pkey: an optional private key to use for authentication
        @type pkey: L{PKey}
        @param key_filename: the filename, or list of filenames, of optional
            private key(s) to try for authentication
        @type key_filename: str or list(str)
        @param timeout: an optional timeout (in seconds) for the TCP connect
        @type timeout: float
        @param allow_agent: set to False to disable connecting to the SSH agent
        @type allow_agent: bool
        """
        self.sshClient = ssh.SSHClient()
        self.sshClient.connect(hostname, port, username, password, pkey, key_filename, timeout, allow_agent)

    def add_command(self, cmd):
        """
        Adds a command to the list that will be executed when exec is called
        :param cmd:
        :return:
        """
        if cmd is None:
            return
        self.commands.append(cmd)

    def exec_command(self, cmd):
        """
        Executes command presented as a set of arguments.
        :param cmd:
        :return: status of execution of the command.
        """
        try:
            resFn = 0
            if cmd is None:
                raise Exception("Unable to exeute: Invalid arguments")
            if self.sshClient is None:
                raise Exception("Unable to execute: Client is not connected")
            ssh_stdin, ssh_stdout, ssh_stderr = self.sshClient.exec_command(cmd["command"])
            fn = cmd["ctl_fn"]
            if "ctl_fn" in cmd:
                resCmd = fn(ssh_stdin, ssh_stdout, ssh_stderr)
                if resCmd == 1:
                    return 2;
            else:
                if "input" in cmd:
                    os.write(ssh_stdin,cmd["input"])
        except Exception:
            return 1

    def exec_commands(self):
        """
        Executed predefined list of commands. The execution terminates when it is done with the list or one of the
        commands returned failure(unix return code != 0) as result of execution.
        :return: total number of executed commands.
        """
        num = 0
        for cmd in self.commands:
            num += 1
            res = self.exec_command(cmd)
            if res != 0:
                return num

