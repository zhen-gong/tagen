import os
import re
import select
import shlex, subprocess

class CmdController(object):
    """
    Works on top of local or remote executor to monitor execution for the list of commands through
    exit status and input/output checking.
    """
    def __init__(self, ctl_fnct, isRemote=False, isWin=False):
        self.ctl_fnct = ctl_fnct
        self.cmd_list = list()

    def add_command(self, cmd):
        self.cmd_list.append(cmd)

    def ctl_fn(self, stdin, stdout, stderr):

        self.ctl_fnct(stdout, stderr)
        return 0

class LocalExec(object):
    """
    Connects to remote host through given ssh connection and executes
    a preset command(s).
    """
    def __init__(self, conf, isWin=False):
        """
        Create new RmtExec object.
        """
        self.conf = conf
        self.commands = list()
        self.isWin = isWin

    def add_command(self, cmd, ctl_fn=None, input=None):
        """
        Adds a command to the list that will be executed when exec is called
        :param cmd:
        :return:
        """
        if cmd is None:
            return
        if ctl_fn is None and input is None:
            self.commands.append(cmd)
            return
        self.commands.append({'command': cmd, 'input': input, 'ctl_fn': ctl_fn})

    def exec_command(self, cmd, ctl_fn=None, input=None):
        """
        Executes command presented as a set of arguments.
        :param cmd:
        :return: status of execution of the command.
        """
        if ctl_fn is not None or input is not None:
            cmd_str = cmd
            cmd = {'command': cmd_str, 'input': input, 'ctl_fn': ctl_fn}
        try:
            resFn = 0
            if cmd is None:
                raise Exception("Unable to exeute: Invalid arguments")
            io_argument = None
            if "ctl_fn" in cmd:
                io_argument = subprocess.PIPE
            sprocess = None
            if not self.isWin:
                sprocess = subprocess.Popen(cmd["command"], stdin=io_argument,
                                                                     stderr=io_argument,
                                                                     stdout=io_argument)
            else:
                cmd_str = cmd["command"]
                args = shlex.split(cmd_str)
                sprocess = subprocess.Popen(args, stdin=io_argument,
                                                                     stderr=io_argument,
                                                                     stdout=io_argument)
            if io_argument != None:
                fn = cmd["ctl_fn"]
                resCmd = fn(self.conf, sprocess)
                if resCmd != 0:
                    return 2
            else:
                if "input" in cmd:
                    os.write(sprocess.stdin, cmd["input"])
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


def expect_line(ptrn_str, process):
    cnt = 10
    output = ""
    while cnt > 0:
        cnt -= 1
        readable, writable, exceptional = select.select([process.stdout, process.stderr], [], [], 10)
        if len(readable) == 0:
            continue
        for s in readable:
            output += os.read(s, 1024)
    match_res = None
    if ptrn_str is not None:
        pattern = re.compile(ptrn_str)
        match_res = pattern.match(output)
    return (output, match_res,
            match_res if match_res is None else match_res.group(0))