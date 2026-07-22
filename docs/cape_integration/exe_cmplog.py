import glob
import logging
import os
import shutil
from subprocess import call

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_APPDATA, OPT_ARGUMENTS, OPT_EXECUTIONDIR, OPT_RUNASX86
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)


class ExeCmplog(Package):
    """EXE-under-cmplog analysis package for Clew Channel 3.

    Runs the supplied executable under the Clew `cmplog` DynamoRIO client, which
    logs, per OP_cmp/OP_test, the runtime comparison operand values (the real
    values an evasion check compares against). Clones exe_drcov.py; the only
    changes are the client DLL, the log dir, and the finish() glob.
    """

    summary = "Runs the supplied executable under the Clew cmplog DynamoRIO client."
    description = (
        "Executes the sample under drrun -c cmplog.dll -logdir; uploads "
        "cmplog.*.log via upload_to_host."
    )

    option_names = (OPT_ARGUMENTS, OPT_APPDATA, OPT_RUNASX86)

    DRRUN = "C:\\dynamorio\\bin32\\drrun.exe"
    # Deploy target for the compiled client inside the guest (mirrors where drcov
    # lives: tools\lib32\release). Push cmplog.dll here in the DR-provisioned snapshot.
    CMPLOG_DLL = "C:\\dynamorio\\tools\\lib32\\release\\cmplog.dll"
    LOGDIR = "C:\\cmp_logs"

    def start(self, path):
        args = self.options.get(OPT_ARGUMENTS)
        appdata = self.options.get(OPT_APPDATA)
        runasx86 = self.options.get(OPT_RUNASX86)

        path = check_file_extension(path, ".exe")

        if appdata:
            basepath = os.getenv("APPDATA")
            newpath = os.path.join(basepath, os.path.basename(path))
            shutil.copy(path, newpath)
            path = newpath
            self.options[OPT_EXECUTIONDIR] = basepath

        if runasx86:
            call(["CorFlags.exe", path, "/32bit+"])

        try:
            os.makedirs(self.LOGDIR, exist_ok=True)
        except Exception as e:
            log.warning("could not create %s: %s", self.LOGDIR, e)

        # Use -c <full_path_to_dll> form, NOT -t <name>, to avoid issue #1750
        # (empty-token bug in drrun's tool option parsing).
        drrun_args = '-c "{}" -logdir "{}" -- "{}"'.format(self.CMPLOG_DLL, self.LOGDIR, path)
        if args:
            drrun_args += " " + args

        log.info("exe_cmplog launching: %s %s", self.DRRUN, drrun_args)
        return self.execute(self.DRRUN, drrun_args, path)

    def finish(self):
        """Upload all cmplog.*.log files from C:\\cmp_logs to the host."""
        try:
            logs = glob.glob(os.path.join(self.LOGDIR, "cmplog.*.log"))
            log.info("exe_cmplog finish: found %d cmplog logs", len(logs))
            for src in logs:
                dst_name = os.path.basename(src)
                try:
                    # "files/" prefix is required: the resultserver allowlist
                    # rejects other prefixes.
                    upload_to_host(src, "files/{}".format(dst_name))
                    log.info("exe_cmplog uploaded %s", dst_name)
                except Exception as e:
                    log.error("upload_to_host failed for %s: %s", src, e)
        except Exception as e:
            log.error("exe_cmplog.finish error: %s", e)
        return True
