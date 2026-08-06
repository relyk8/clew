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


class ExeDrtrace(Package):
    """EXE-under-drtrace analysis package for Clew Channel 3.

    Runs the supplied executable under the Clew `drtrace` DynamoRIO client, which
    traces the environment-sensitive Windows API calls the sample makes (call
    site, arguments, return value, out-parameters) alongside the runtime
    comparison operands those values are checked against.

    Supersedes exe_cmplog.py, which logged only the comparisons. exe_cmplog is
    kept in place so the previous client stays runnable during the transition.

    NOTE: submit with `options=free=yes`. CAPE's monitor injects into drrun.exe
    and corrupts DynamoRIO, which self-terminates about a second in and produces
    no logs at all.
    """

    summary = "Runs the supplied executable under the Clew drtrace DynamoRIO client."
    description = (
        "Executes the sample under drrun -c drtrace.dll -logdir; uploads "
        "drtrace.*.log (per-thread traces and the module table) via upload_to_host."
    )

    option_names = (OPT_ARGUMENTS, OPT_APPDATA, OPT_RUNASX86)

    DRRUN = "C:\\dynamorio\\bin32\\drrun.exe"
    # Deploy target for the compiled client inside the guest (mirrors where drcov
    # lives: tools\lib32\release). Push drtrace.dll here in the DR-provisioned
    # snapshot.
    DRTRACE_DLL = "C:\\dynamorio\\tools\\lib32\\release\\drtrace.dll"
    LOGDIR = "C:\\drtrace_logs"

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
        drrun_args = '-c "{}" -logdir "{}" -- "{}"'.format(self.DRTRACE_DLL, self.LOGDIR, path)
        if args:
            drrun_args += " " + args

        log.info("exe_drtrace launching: %s %s", self.DRRUN, drrun_args)
        return self.execute(self.DRRUN, drrun_args, path)

    def finish(self):
        """Upload all drtrace.*.log files from C:\\drtrace_logs to the host.

        The glob deliberately covers both the per-thread traces
        (drtrace.<pid>.<tid>.log) and the process-wide module table
        (drtrace.<pid>.modules.log); the host dispatches on record type, not on
        filename, and it needs the module table to rebase PCs.
        """
        try:
            logs = glob.glob(os.path.join(self.LOGDIR, "drtrace.*.log"))
            log.info("exe_drtrace finish: found %d drtrace logs", len(logs))
            for src in logs:
                dst_name = os.path.basename(src)
                try:
                    # "files/" prefix is required: the resultserver allowlist
                    # rejects other prefixes.
                    upload_to_host(src, "files/{}".format(dst_name))
                    log.info("exe_drtrace uploaded %s", dst_name)
                except Exception as e:
                    log.error("upload_to_host failed for %s: %s", src, e)
        except Exception as e:
            log.error("exe_drtrace.finish error: %s", e)
        return True
