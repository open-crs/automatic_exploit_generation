import logging
import os
import tempfile
import typing
from dataclasses import dataclass
from enum import Enum, auto

import pwn

from automatic_exploit_generation.exceptions import ExploitingException

ProcessInput = typing.Union[bytes, typing.List[bytes]]


class InputStream(Enum):
    FILES = auto()
    STDIN = auto()
    ARGUMENTS = auto()


@dataclass
class Process:
    path: str = None
    process: pwn.process = None
    pid: int = None
    input_stream: InputStream = None
    sent_input: ProcessInput = None
    output: bytes = None


def create_process(
    path: str,
    input_stream: InputStream,
    sent_input: ProcessInput,
) -> Process:
    process = Process(
        path=path, input_stream=input_stream, sent_input=sent_input
    )

    return process


def execute_process(process: Process) -> None:
    created_process = create_process_depending_on_input_stream(process)
    output = created_process.recvall()

    process.process = created_process
    process.output = output
    process.pid = created_process.proc


def create_process_depending_on_input_stream(process: Process) -> pwn.process:
    if process.input_stream == InputStream.FILES:
        file = tempfile.NamedTemporaryFile("wb", delete=False)
        file.write(process.sent_input)
        file.flush()
        file.close()

        process = create_process_with_file_as_argument(process, file.name)
    elif process.input_stream == InputStream.STDIN:
        process = create_process_with_stdin(process)
    elif process.input_stream == InputStream.ARGUMENTS:
        process = create_process_with_arguments(process)

    return process


def create_process_with_file_as_argument(
    process: Process, filename: str
) -> pwn.process:
    filename_enc = filename.encode("utf-8")

    return create_process_with_arguments(process, [filename_enc])


def create_process_with_arguments(
    process: Process, overwritten_args: typing.List[bytes] = None
) -> pwn.process:
    if overwritten_args:
        arguments = overwritten_args
    else:
        if not isinstance(process.sent_input, list):
            raise InvalidInputType()
        else:
            arguments = process.sent_input

    return pwn.process([process.path, *arguments])


def create_process_with_stdin(process: Process) -> pwn.process:
    if not isinstance(process.sent_input, bytes):
        raise InvalidInputType()

    new_process = pwn.process([process.path])
    new_process.send(process.sent_input)

    return new_process


def generate_core_filename(pid: int, executable_name: str) -> str:
    uid = os.getuid()

    return f"/var/crash/core.{pid}.{uid}.{executable_name}"


def get_core(process: Process) -> pwn.Coredump:
    crash_filename = generate_core_filename(process.pid, process.path)
    logging.info("Crash filename: %s", crash_filename)

    if not os.path.exists(crash_filename):
        raise CoreNotGeneratedException()

    core = pwn.Coredump(crash_filename, checksec=False)

    return core


class CoreNotGeneratedException(ExploitingException):
    """The core was not generated."""


class InvalidInputType(ExploitingException):
    """The provided initial input does not match the one requird by the sream.
    """
