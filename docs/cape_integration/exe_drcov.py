import os
import glob
import shutil
import logging
from subprocess import call

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_APPDATA, OPT_ARGUMENTS, OPT_EXECUTIONDIR, OPT_RUNASX86
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)


class ExeDrcov(Package):
    """EXE-under-drcov analysis package for Clew Channel 4 pilot."""

    summary = "Runs the supplied executable under DynamoRIO drcov for coverage logging."
    description = "Executes the sample under drrun -c drcov.dll -logdir; uploads drcov.*.log via upload_to_host."

    option_names = (OPT_ARGUMENTS, OPT_APPDATA, OPT_RUNASX86)

    DRRUN = "C:\\dynamorio\\bin32\\drrun.exe"
    DRCOV_DLL = "C:\\dynamorio\\tools\\lib32\\release\\drcov.dll"
    LOGDIR = "C:\\drcov_logs"

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

        # Use -c <full_path_to_dll> form, NOT -t drcov, to avoid issue #1750
        # (empty-token bug in drrun's tool option parsing).
        drrun_args = '-c "{}" -logdir "{}" -- "{}"'.format(
            self.DRCOV_DLL, self.LOGDIR, path
        )
        if args:
            drrun_args += " " + args

        log.info("exe_drcov launching: %s %s", self.DRRUN, drrun_args)
        return self.execute(self.DRRUN, drrun_args, path)

    def finish(self):
        """Upload all drcov.*.log files from C:\\drcov_logs to the host."""
        try:
            logs = glob.glob(os.path.join(self.LOGDIR, "drcov.*.log"))
            log.info("exe_drcov finish: found %d drcov logs", len(logs))
            for src in logs:
                dst_name = os.path.basename(src)
                try:
                    upload_to_host(src, "files/{}".format(dst_name))
                    log.info("exe_drcov uploaded %s", dst_name)
                except Exception as e:
                    log.error("upload_to_host failed for %s: %s", src, e)
        except Exception as e:
            log.error("exe_drcov.finish error: %s", e)
        return True
