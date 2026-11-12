# main.py - starts the Data Sentinel conductor
#
# The build cycle is the V1 conductor's: requirements.txt, Dockerfile, main.py.
# SOURCEdefender is not used in this build (Kevin, 2026-11-11); when it comes back,
# the import goes on the next line, before ds_conductor is loaded:
# import sourcedefender
import os
import sys
import signal
import logging

import uvicorn

import ds_conductor


def main():
    try:
        settings = ds_conductor.load_settings()
    except ds_conductor.SettingsError as e:
        # a setting that can't be used stops the process with a message that names it
        sys.stderr.write("ds_conductor cannot start: " + str(e) + "\n")
        return 2
    ds_conductor.setup_logging(settings)
    # uvicorn stops the service on SIGTERM and then hands the signal back to whoever had it
    # before. That is this: nothing more to do, so the process ends with its own exit code
    # (0 after a clean stop, 1 after a configuration error) and not "killed by signal".
    for _sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(_sig, lambda *_a: None)
    config = uvicorn.Config("ds_conductor:app", host="0.0.0.0", port=settings.port,
                            log_config=None, access_log=False,
                            timeout_graceful_shutdown=5)
    uvicorn.Server(config).run()
    return ds_conductor.conductor.exit_code if ds_conductor.conductor is not None else 1


if __name__ == "__main__":
    _code = main()
    logging.shutdown()
    # a check thread the conductor gave up on can't be killed, and must not hold the exit
    os._exit(_code)
