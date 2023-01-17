import logging
import typing
from enum import Enum, auto

from pwn import ELF

SENSITIVE_STRINGS = ["win", "secret", "shell", "system", "flag"]


class Mitigation(Enum):
    ASLR = auto()
    NX = auto()
    CANARY = auto()
    RELRO = auto()
    PIE = auto()
    FORTIFY = auto()
    ASAN = auto()


class ContextAspects(Enum):
    EXECSTACK = auto()
    RWX_SEGMENTS = auto()


def get_mitigations(binary: ELF) -> list(Mitigation):
    yield from __get_members_from_loaded_elf(binary, Mitigation)


def get_context_aspects(binary: ELF) -> list(ContextAspects):
    yield from __get_members_from_loaded_elf(binary, ContextAspects)


def __get_members_from_loaded_elf(
    binary: ELF, members_enum: Enum
) -> typing.Generator[Enum, None, None]:
    for member in members_enum:
        member_name = member.name
        if getattr(binary, member_name.lower(), False):
            logging.info("Found set member of binary: %s", member_name)

            yield members_enum[member_name]


def get_sensitive_functions_addresses(
    binary: ELF,
) -> typing.Generator[int, None, None]:
    funcs = {
        name: address
        for name, address in binary.symbols.items()
        if __is_sensitive(name)
    }

    for name, address in funcs.items():
        logging.info("Found sensitive function: %s (%s)", name, hex(address))

    yield from funcs


def __is_sensitive(function_name: str) -> bool:
    return any([string in function_name for string in SENSITIVE_STRINGS])
