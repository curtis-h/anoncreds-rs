"""Low-level interaction with the indy-credx library."""

import json
import logging
import os
import sys
from ctypes import (
    byref,
    c_char_p,
    c_int8,
    c_int64,
    c_size_t,
    c_void_p,
    pointer,
    CDLL,
    POINTER,
    Structure,
)
from ctypes.util import find_library
from typing import Optional, Mapping, Sequence, Union

from .error import CredxError, CredxErrorCode


CALLBACKS = {}
LIB: CDLL = None
LOGGER = logging.getLogger(__name__)


class ObjectHandle(c_int64):
    """Index of an active IndyObject instance."""

    @property
    def type_name(self) -> str:
        return object_get_type_name(self)

    def __repr__(self) -> str:
        """Format object handle as a string."""
        return f'{self.__class__.__name__}("{self.type_name}", {self.value})'

    def __del__(self):
        object_free(self)


class IndyObject:
    """A generic Indy object allocated by the library."""

    def __init__(self, handle: ObjectHandle) -> "IndyObject":
        self.handle = handle

    def __repr__(self) -> str:
        """Format object as a string."""
        return f"{self.__class__.__name__}({self.handle.value})"

    def to_json(self) -> str:
        return str(object_get_json(self.handle))


class lib_string(c_char_p):
    """A string allocated by the library."""

    @classmethod
    def from_param(cls):
        """Returns the type ctypes should use for loading the result."""
        return c_void_p

    def is_none(self) -> bool:
        return self.value is None

    def opt_str(self) -> Optional[str]:
        return self.value.decode("utf-8") if self.value is not None else None

    def __bytes__(self):
        """Convert to bytes."""
        return self.value

    def __str__(self):
        """Convert to str."""
        # not allowed to return None
        return self.value.decode("utf-8") if self.value is not None else ""

    def __del__(self):
        """Call the string destructor when this instance is released."""
        get_library().credx_string_free(self)


class object_handle_list(Structure):
    _fields_ = [
        ("count", c_size_t),
        ("data", POINTER(ObjectHandle)),
    ]

    @classmethod
    def create(cls, values: Optional[Sequence[ObjectHandle]]) -> "object_handle_list":
        inst = object_handle_list()
        if values is not None:
            values = list(values)
            inst.count = len(values)
            inst.data = (ObjectHandle * inst.count)(*values)
        return inst


class int_list(Structure):
    _fields_ = [
        ("count", c_size_t),
        ("data", POINTER(c_int64)),
    ]

    @classmethod
    def create(cls, values: Optional[Sequence[str]]) -> "int_list":
        inst = int_list()
        if values is not None:
            values = [c_int64(v) for v in values]
            inst.count = len(values)
            inst.data = (c_int64 * inst.count)(*values)
        return inst


class str_list(Structure):
    _fields_ = [
        ("count", c_size_t),
        ("data", POINTER(c_char_p)),
    ]

    @classmethod
    def create(cls, values: Optional[Sequence[str]]) -> "str_list":
        inst = str_list()
        if values is not None:
            values = [encode_str(v) for v in values]
            inst.count = len(values)
            inst.data = (c_char_p * inst.count)(*values)
        return inst


class CredentialEntry(Structure):
    _fields_ = [
        ("credential", ObjectHandle),
        ("timestamp", c_int64),
        ("rev_state", ObjectHandle),
    ]

    @classmethod
    def create(
        cls,
        credential: ObjectHandle,
        timestamp: int = None,
        rev_state: ObjectHandle = None,
    ) -> "CredentialEntry":
        return CredentialEntry(
            credential=credential,
            timestamp=-1 if timestamp is None else timestamp,
            rev_state=rev_state or ObjectHandle(),
        )


class CredentialEntryList(Structure):
    _fields_ = [
        ("count", c_int64),
        ("data", POINTER(CredentialEntry)),
    ]


class CredentialProve(Structure):
    _fields_ = [
        ("entry_idx", c_int64),
        ("referent", c_char_p),
        ("is_predicate", c_int8),
        ("reveal", c_int8),
    ]

    @classmethod
    def attribute(
        cls,
        entry_idx: int,
        referent: str,
        reveal: bool,
    ) -> "CredentialProve":
        return CredentialProve(
            entry_idx=entry_idx,
            referent=encode_str(referent),
            is_predicate=False,
            reveal=reveal,
        )

    @classmethod
    def predicate(
        cls,
        entry_idx: int,
        referent: str,
    ) -> "CredentialProve":
        return CredentialProve(
            entry_idx=entry_idx,
            referent=encode_str(referent),
            is_predicate=True,
            reveal=True,
        )


class CredentialProveList(Structure):
    _fields_ = [
        ("count", c_int64),
        ("data", POINTER(CredentialProve)),
    ]


class RevocationConfig(Structure):
    _fields_ = [
        ("rev_reg_def", ObjectHandle),
        ("rev_reg_def_private", ObjectHandle),
        ("rev_reg", ObjectHandle),
        ("rev_reg_index", c_int64),
        ("tails_path", c_char_p),
    ]

    @classmethod
    def create(
        cls,
        rev_reg_def: ObjectHandle,
        rev_reg_def_private: ObjectHandle,
        rev_reg: ObjectHandle,
        rev_reg_index: int,
        tails_path: str,
    ) -> "RevocationConfig":
        return RevocationConfig(
            rev_reg_def=rev_reg_def,
            rev_reg_def_private=rev_reg_def_private,
            rev_reg=rev_reg,
            rev_reg_index=rev_reg_index,
            tails_path=encode_str(tails_path),
        )


class RevocationEntry(Structure):
    _fields_ = [
        ("def_entry_idx", c_int64),
        ("entry", ObjectHandle),
        ("timestamp", c_int64),
    ]

    @classmethod
    def create(
        cls,
        def_entry_idx: int,
        entry: ObjectHandle,
        timestamp: int,
    ) -> "RevocationEntry":
        return RevocationEntry(
            def_entry_idx=def_entry_idx,
            entry=entry,
            timestamp=timestamp,
        )


class RevocationEntryList(Structure):
    _fields_ = [
        ("count", c_int64),
        ("data", POINTER(RevocationEntry)),
    ]


def get_library() -> CDLL:
    """Return the CDLL instance, loading it if necessary."""
    global LIB
    if LIB is None:
        LIB = _load_library("indy_credx")
        do_call("credx_set_default_logger")
    return LIB


def library_version() -> str:
    """Get the version of the installed aries-askar library."""
    lib = get_library()
    lib.credx_version.restype = c_void_p
    return str(lib_string(lib.credx_version()))


def _load_library(lib_name: str) -> CDLL:
    """Load the CDLL library.
    The python module directory is searched first, followed by the usual
    library resolution for the current system.
    """
    lib_prefix_mapping = {"win32": ""}
    lib_suffix_mapping = {"darwin": ".dylib", "win32": ".dll"}
    try:
        os_name = sys.platform
        lib_prefix = lib_prefix_mapping.get(os_name, "lib")
        lib_suffix = lib_suffix_mapping.get(os_name, ".so")
        lib_path = os.path.join(
            os.path.dirname(__file__), f"{lib_prefix}{lib_name}{lib_suffix}"
        )
        return CDLL(lib_path)
    except KeyError:
        LOGGER.debug("Unknown platform for shared library")
    except OSError:
        LOGGER.warning("Library not loaded from python package")

    lib_path = find_library(lib_name)
    if not lib_path:
        raise CredxError(CredxErrorCode.WRAPPER, f"Error loading library: {lib_name}")
    try:
        return CDLL(lib_path)
    except OSError as e:
        raise CredxError(
            CredxErrorCode.WRAPPER, f"Error loading library: {lib_name}"
        ) from e


def do_call(fn_name, *args):
    """Perform a synchronous library function call."""
    lib_fn = getattr(get_library(), fn_name)
    result = lib_fn(*args)
    if result:
        raise get_current_error(True)


def get_current_error(expect: bool = False) -> Optional[CredxError]:
    """
    Get the error result from the previous failed API method.

    Args:
        expect: Return a default error message if none is found
    """
    err_json = lib_string()
    if not get_library().credx_get_current_error(byref(err_json)):
        try:
            msg = json.loads(err_json.value)
        except json.JSONDecodeError:
            LOGGER.warning("JSON decode error for credx_get_current_error")
            msg = None
        if msg and "message" in msg and "code" in msg:
            return CredxError(
                CredxErrorCode(msg["code"]), msg["message"], msg.get("extra")
            )
        if not expect:
            return None
    return CredxError(CredxErrorCode.WRAPPER, "Unknown error")


def decode_str(value: c_char_p) -> str:
    return value.decode("utf-8")


def encode_str(arg: Optional[Union[str, bytes, memoryview]]) -> c_char_p:
    """
    Encode an optional input argument as a string.

    Returns: None if the argument is None, otherwise the value encoded utf-8.
    """
    if arg is None:
        return c_char_p()
    if isinstance(arg, str):
        return c_char_p(arg.encode("utf-8"))
    return c_char_p(arg)


def object_free(handle: ObjectHandle):
    get_library().credx_object_free(handle)


def object_get_json(handle: ObjectHandle) -> lib_string:
    result = lib_string()
    do_call("credx_object_get_json", handle, byref(result))
    return result


def object_get_type_name(handle: ObjectHandle) -> lib_string:
    result = lib_string()
    do_call("credx_object_get_type_name", handle, byref(result))
    return result


def _object_from_json(
    method: str, value: Union[dict, str, bytes, memoryview]
) -> ObjectHandle:
    if isinstance(value, dict):
        value = json.dumps(value)
    result = ObjectHandle()
    do_call(method, encode_str(value), byref(result))
    return result


def _object_get_attribute(
    method: str, handle: ObjectHandle, name: str
) -> Optional[lib_string]:
    result = lib_string()
    do_call(method, handle, encode_str(name), byref(result))
    if result.is_none():
        result = None
    return result


def generate_nonce() -> str:
    result = lib_string()
    do_call("credx_generate_nonce", byref(result))
    return str(result)


def create_schema(
    origin_did: str,
    name: str,
    version: str,
    attr_names: Sequence[str],
    seq_no: int = None,
) -> ObjectHandle:
    result = ObjectHandle()
    attrs = str_list.create(attr_names)
    do_call(
        "credx_create_schema",
        encode_str(origin_did),
        encode_str(name),
        encode_str(version),
        attrs,
        c_int64(seq_no or -1),
        byref(result),
    )
    return result


def create_credential_definition(
    origin_did: str,
    schema: ObjectHandle,
    tag: str,
    signature_type: str,
    support_revocation: bool,
) -> (ObjectHandle, ObjectHandle, ObjectHandle):
    cred_def, cred_def_pvt, key_proof = ObjectHandle(), ObjectHandle(), ObjectHandle()
    do_call(
        "credx_create_credential_definition",
        encode_str(origin_did),
        schema,
        encode_str(tag),
        encode_str(signature_type),
        c_int8(support_revocation),
        byref(cred_def),
        byref(cred_def_pvt),
        byref(key_proof),
    )
    return (cred_def, cred_def_pvt, key_proof)


def create_credential(
    cred_def: ObjectHandle,
    cred_def_private: ObjectHandle,
    cred_offer: ObjectHandle,
    cred_request: ObjectHandle,
    attr_raw_values: Mapping[str, str],
    attr_enc_values: Optional[Mapping[str, str]],
    revocation_config: Optional[RevocationConfig],
) -> (ObjectHandle, ObjectHandle, ObjectHandle):
    cred = ObjectHandle()
    rev_reg = ObjectHandle()
    rev_delta = ObjectHandle()
    names_list = str_list.create(attr_raw_values.keys())
    raw_values_list = str_list.create(attr_raw_values.values())
    if attr_enc_values:
        enc_values_list = []
        for name in attr_raw_values:
            enc_values_list.append(attr_enc_values.get(name))
    else:
        enc_values_list = None
    enc_values_list = str_list().create(enc_values_list)
    do_call(
        "credx_create_credential",
        cred_def,
        cred_def_private,
        cred_offer,
        cred_request,
        names_list,
        raw_values_list,
        enc_values_list,
        pointer(revocation_config)
        if revocation_config
        else POINTER(RevocationConfig)(),
        byref(cred),
        byref(rev_reg),
        byref(rev_delta),
    )
    return cred, rev_reg, rev_delta


def process_credential(
    cred: ObjectHandle,
    cred_req_metadata: ObjectHandle,
    master_secret: ObjectHandle,
    cred_def: ObjectHandle,
    rev_reg_def: Optional[ObjectHandle],
) -> ObjectHandle:
    result = ObjectHandle()
    do_call(
        "credx_process_credential",
        cred,
        cred_req_metadata,
        master_secret,
        cred_def,
        rev_reg_def or ObjectHandle(),
        byref(result),
    )
    return result


def revoke_credential(
    rev_reg_def: ObjectHandle,
    rev_reg: ObjectHandle,
    cred_rev_idx: int,
    tails_path: str,
) -> (ObjectHandle, ObjectHandle):
    upd_rev_reg = ObjectHandle()
    rev_delta = ObjectHandle()
    do_call(
        "credx_revoke_credential",
        rev_reg_def,
        rev_reg,
        c_int64(cred_rev_idx),
        encode_str(tails_path),
        byref(upd_rev_reg),
        byref(rev_delta),
    )
    return upd_rev_reg, rev_delta


def create_credential_offer(
    schema_id: str, cred_def: ObjectHandle, key_proof: ObjectHandle
) -> ObjectHandle:
    cred_offer = ObjectHandle()
    do_call(
        "credx_create_credential_offer",
        encode_str(schema_id),
        cred_def,
        key_proof,
        byref(cred_offer),
    )
    return cred_offer


def create_credential_request(
    prover_did: str,
    cred_def: ObjectHandle,
    master_secret: ObjectHandle,
    master_secret_id: str,
    cred_offer: ObjectHandle,
) -> (ObjectHandle, ObjectHandle):
    cred_req, cred_req_metadata = ObjectHandle(), ObjectHandle()
    do_call(
        "credx_create_credential_request",
        encode_str(prover_did),
        cred_def,
        master_secret,
        encode_str(master_secret_id),
        cred_offer,
        byref(cred_req),
        byref(cred_req_metadata),
    )
    return (cred_req, cred_req_metadata)


def create_master_secret() -> ObjectHandle:
    secret = ObjectHandle()
    do_call(
        "credx_create_master_secret",
        byref(secret),
    )
    return secret


def create_presentation(
    pres_req: ObjectHandle,
    credentials: Sequence[CredentialEntry],
    credentials_prove: Sequence[CredentialProve],
    self_attest: Mapping[str, str],
    master_secret: ObjectHandle,
    schemas: Sequence[ObjectHandle],
    cred_defs: Sequence[ObjectHandle],
) -> ObjectHandle:
    entry_list = CredentialEntryList()
    entry_list.count = len(credentials)
    entry_list.data = (CredentialEntry * entry_list.count)(*credentials)
    prove_list = CredentialProveList()
    prove_list.count = len(credentials_prove)
    prove_list.data = (CredentialProve * prove_list.count)(*credentials_prove)
    present = ObjectHandle()
    do_call(
        "credx_create_presentation",
        pres_req,
        entry_list,
        prove_list,
        str_list.create(self_attest.keys()),
        str_list.create(self_attest.values()),
        master_secret,
        object_handle_list.create(schemas),
        object_handle_list.create(cred_defs),
        byref(present),
    )
    return present


def verify_presentation(
    presentation: ObjectHandle,
    pres_req: ObjectHandle,
    schemas: Sequence[ObjectHandle],
    cred_defs: Sequence[ObjectHandle],
    rev_reg_defs: Sequence[ObjectHandle],
    rev_regs: Sequence[RevocationEntry],
) -> bool:
    verify = c_int8()
    entry_list = RevocationEntryList()
    if rev_regs:
        entry_list.count = len(rev_regs)
        entry_list.data = (RevocationEntry * entry_list.count)(*rev_regs)
    do_call(
        "credx_verify_presentation",
        presentation,
        pres_req,
        object_handle_list.create(schemas),
        object_handle_list.create(cred_defs),
        object_handle_list.create(rev_reg_defs),
        entry_list,
        byref(verify),
    )
    return bool(verify)


def create_revocation_registry(
    origin_did: str,
    cred_def: ObjectHandle,
    tag: str,
    rev_reg_type: str,
    issuance_type: Optional[str],
    max_cred_num: int,
    tails_dir_path: Optional[str],
) -> (ObjectHandle, ObjectHandle, ObjectHandle, ObjectHandle):
    reg_def = ObjectHandle()
    reg_def_private = ObjectHandle()
    reg_entry = ObjectHandle()
    reg_init_delta = ObjectHandle()
    do_call(
        "credx_create_revocation_registry",
        encode_str(origin_did),
        cred_def,
        encode_str(tag),
        encode_str(rev_reg_type),
        encode_str(issuance_type),
        c_int64(max_cred_num),
        encode_str(tails_dir_path),
        byref(reg_def),
        byref(reg_def_private),
        byref(reg_entry),
        byref(reg_init_delta),
    )
    return reg_def, reg_def_private, reg_entry, reg_init_delta


def update_revocation_registry(
    rev_reg_def: ObjectHandle,
    rev_reg: ObjectHandle,
    issued: Sequence[int],
    revoked: Sequence[int],
    tails_path: str,
) -> (ObjectHandle, ObjectHandle):
    upd_rev_reg = ObjectHandle()
    rev_delta = ObjectHandle()
    do_call(
        "credx_update_revocation_registry",
        rev_reg_def,
        rev_reg,
        int_list.create(issued),
        int_list.create(revoked),
        encode_str(tails_path),
        byref(upd_rev_reg),
        byref(rev_delta),
    )
    return upd_rev_reg, rev_delta


def create_or_update_revocation_state(
    rev_reg_def: ObjectHandle,
    rev_reg_delta: ObjectHandle,
    rev_reg_index: int,
    timestamp: int,
    tails_path: str,
    prev_rev_state: Optional[ObjectHandle],
) -> ObjectHandle:
    rev_state = ObjectHandle()
    do_call(
        "credx_create_or_update_revocation_state",
        rev_reg_def,
        rev_reg_delta,
        c_int64(rev_reg_index),
        c_int64(timestamp),
        encode_str(tails_path),
        prev_rev_state or ObjectHandle(),
        byref(rev_state),
    )
    return rev_state
