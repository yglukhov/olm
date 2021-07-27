import strutils
from os import quoteShell, DirSep, AltSep

const
  olmVer = "3.2.4".split(".")
  csrcPath = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0] & "/olm/csources/olm/"
  olmPath = csrcPath & "src/"
  includePath = csrcPath & "include"
  olmFlags = "-I" & includePath & " -I" & csrcPath & "lib" &
    " -DOLMLIB_VERSION_MAJOR=" & olmVer[0] &
    " -DOLMLIB_VERSION_MINOR=" & olmVer[1] &
    " -DOLMLIB_VERSION_PATCH=" & olmVer[2]

  cryalgPath = csrcPath & "lib/crypto-algorithms/"
  cryalgFlags = ""

  donnaPath = csrcPath & "lib/curve25519-donna/"
  donnaFlags = ""

when not defined(cpp):
  {.passL: "-lstdc++"}

{.compile(olmPath & "account.cpp", olmFlags).}
{.compile(olmPath & "base64.cpp", olmFlags).}
{.compile(olmPath & "cipher.cpp", olmFlags).}
{.compile(olmPath & "crypto.cpp", olmFlags).}
{.compile(olmPath & "ed25519.c", olmFlags).}
{.compile(olmPath & "error.c", olmFlags).}
{.compile(olmPath & "inbound_group_session.c", olmFlags).}
{.compile(olmPath & "megolm.c", olmFlags).}
{.compile(olmPath & "memory.cpp", olmFlags).}
{.compile(olmPath & "message.cpp", olmFlags).}
{.compile(olmPath & "olm.cpp", olmFlags).}
{.compile(olmPath & "outbound_group_session.c", olmFlags).}
{.compile(olmPath & "pickle.cpp", olmFlags).}
{.compile(olmPath & "pickle_encoding.c", olmFlags).}
{.compile(olmPath & "pk.cpp", olmFlags).}
{.compile(olmPath & "ratchet.cpp", olmFlags).}
{.compile(olmPath & "sas.c", olmFlags).}
{.compile(olmPath & "session.cpp", olmFlags).}
{.compile(olmPath & "utility.cpp", olmFlags).}

{.compile(cryalgPath & "aes.c", cryalgFlags).}
{.compile(cryalgPath & "arcfour.c", cryalgFlags).}
{.compile(cryalgPath & "base64.c", cryalgFlags).}
{.compile(cryalgPath & "blowfish.c", cryalgFlags).}
{.compile(cryalgPath & "des.c", cryalgFlags).}
{.compile(cryalgPath & "md2.c", cryalgFlags).}
{.compile(cryalgPath & "md5.c", cryalgFlags).}
{.compile(cryalgPath & "rot-13.c", cryalgFlags).}
{.compile(cryalgPath & "sha1.c", cryalgFlags).}
{.compile(cryalgPath & "sha256.c", cryalgFlags).}

{.compile(donnaPath & "curve25519-donna.c", cryalgFlags).}


const
  OLM_MESSAGE_TYPE_PRE_KEY = 0.csize_t
  OLM_MESSAGE_TYPE_MESSAGE = 1.csize_t

type
  Account* = ptr object
  Session* = ptr object
  Utility* = ptr object


proc getLibraryVersion*(major, minor, patch: ptr uint8) {.importc: "olm_get_library_version".}
## Get the version number of the library.
## Arguments will be updated if non-null.

proc accountSize*(): csize_t {.importc: "olm_account_size".}
## The size of an account object in bytes

proc sessionSize*(): csize_t {.importc: "olm_session_size".}
## The size of a session object in bytes

proc utilitySize*(): csize_t {.importc: "olm_utility_size".}
## The size of a utility object in bytes

proc initAccount*(memory: pointer): Account {.importc: "olm_account".}
## Initialise an account object using the supplied memory
##  The supplied memory must be at least olm_account_size() bytes

proc initSession*(memory: pointer): Session {.importc: "olm_session".}
## Initialise a session object using the supplied memory
##  The supplied memory must be at least olm_session_size() bytes

proc initUtility*(memory: pointer): Utility {.importc: "olm_utility".}
## Initialise a utility object using the supplied memory
##  The supplied memory must be at least olm_utility_size() bytes

proc error*(): csize_t {.importc: "olm_error".}
## The value that olm will return from a function if there was an error

proc lastError*(account: Account): cstring {.importc: "olm_account_last_error".}
## A null terminated string describing the most recent error to happen to an
## account

proc lastError*(session: Session): cstring {.importc: "olm_session_last_error".}
## A null terminated string describing the most recent error to happen to a
## session

proc lastError*(utility: Utility): cstring {.importc: "olm_utility_last_error".}
## A null terminated string describing the most recent error to happen to a
## utility

proc clear*(a: Account): csize_t {.importc: "olm_clear_account".}
## Clears the memory used to back this account

proc clear*(m: Session): csize_t {.importc: "olm_clear_session".}
## Clears the memory used to back this session

proc clear*(m: Utility): csize_t {.importc: "olm_clear_utility".}
## Clears the memory used to back this utility

proc pickleLength*(a: Account): csize_t {.importc: "olm_pickle_account_length".}
## Returns the number of bytes needed to store an account

proc pickleLength*(s: Session): csize_t {.importc: "olm_pickle_session_length".}
## Returns the number of bytes needed to store a session

proc pickle*(a: Account, key: pointer, keyLength: csize_t, pickled: pointer, pickled_length: csize_t): csize_t {.importc: "olm_pickle_account".}
## Stores an account as a base64 string. Encrypts the account using the
## supplied key. Returns the length of the pickled account on success.
## Returns olm_error() on failure. If the pickle output buffer
## is smaller than olm_pickle_account_length() then
## olm_account_last_error() will be "OUTPUT_BUFFER_TOO_SMALL"

proc pickle*(s: Session, key: pointer, keyLength: csize_t, pickled: pointer, pickled_length: csize_t): csize_t {.importc: "olm_pickle_session".}
## Stores a session as a base64 string. Encrypts the session using the
## supplied key. Returns the length of the pickled session on success.
## Returns olm_error() on failure. If the pickle output buffer
## is smaller than olm_pickle_session_length() then
## olm_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL"

proc unpickle*(a: Account, key: pointer, keyLength: csize_t, pickled: pointer, pickled_length: csize_t): csize_t {.importc: "olm_unpickle_account".}
## Loads an account from a pickled base64 string. Decrypts the account using
## the supplied key. Returns olm_error() on failure. If the key doesn't
## match the one used to encrypt the account then olm_account_last_error()
## will be "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
## olm_account_last_error() will be "INVALID_BASE64". The input pickled
## buffer is destroyed

proc unpickle*(s: Session, key: pointer, keyLength: csize_t, pickled: pointer, pickled_length: csize_t): csize_t {.importc: "olm_unpickle_session".}
## Loads a session from a pickled base64 string. Decrypts the session using
## the supplied key. Returns olm_error() on failure. If the key doesn't
## match the one used to encrypt the account then olm_session_last_error()
## will be "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
## olm_session_last_error() will be "INVALID_BASE64". The input pickled
## buffer is destroyed

proc createAccountRandomLength*(a: Account): csize_t {.importc: "olm_create_account_random_length".}
## The number of random bytes needed to create an account.

proc create*(a: Account, random: pointer, random_length: csize_t): csize_t {.importc: "olm_create_account".}
## Creates a new account. Returns olm_error() on failure. If there weren't
## enough random bytes then olm_account_last_error() will be
## "NOT_ENOUGH_RANDOM"

proc identityKeysLength*(a: Account): csize_t {.importc: "olm_account_identity_keys_length".}
## The size of the output buffer needed to hold the identity keys

proc identityKeys*(a: Account, identity_keys: pointer, identity_key_length: csize_t): csize_t {.importc: "olm_account_identity_keys"}
## Writes the public parts of the identity keys for the account into the
## identity_keys output buffer. Returns olm_error() on failure. If the
## identity_keys buffer was too small then olm_account_last_error() will be
## "OUTPUT_BUFFER_TOO_SMALL".

proc signatureLength*(a: Account): csize_t {.importc: "olm_account_signature_length"}
## The length of an ed25519 signature encoded as base64.

proc sign*(a: Account, message: pointer, message_length: csize_t, signature: pointer, signature_length: csize_t): csize_t {.importc: "olm_account_sign".}
## Signs a message with the ed25519 key for this account. Returns olm_error()
## on failure. If the signature buffer was too small then
## olm_account_last_error() will be "OUTPUT_BUFFER_TOO_SMALL"

proc oneTimeKeysLength*(a: Account): csize_t {.importc: "olm_account_one_time_keys_length".}
## The size of the output buffer needed to hold the one time keys

proc oneTimeKeys*(a: Account, one_time_keys: pointer, one_time_keys_length: csize_t): csize_t {.importc: "olm_account_one_time_keys".}
## Writes the public parts of the unpublished one time keys for the account
## into the one_time_keys output buffer.
## <p>
## The returned data is a JSON-formatted object with the single property
## <tt>curve25519</tt>, which is itself an object mapping key id to
## base64-encoded Curve25519 key. For example:
## <pre>
## {
##     curve25519: {
##         "AAAAAA": "wo76WcYtb0Vk/pBOdmduiGJ0wIEjW4IBMbbQn7aSnTo",
##         "AAAAAB": "LRvjo46L1X2vx69sS9QNFD29HWulxrmW11Up5AfAjgU"
##     }
## }
## </pre>
## Returns olm_error() on failure.
## <p>
## If the one_time_keys buffer was too small then olm_account_last_error()
## will be "OUTPUT_BUFFER_TOO_SMALL".

proc markKeysAsPublished*(a: Account): csize_t {.importc: "olm_account_mark_keys_as_published".}
## Marks the current set of one time keys as being published.

proc maxNumberOfOneTimeKeys*(a: Account): csize_t {.importc: "olm_account_max_number_of_one_time_keys".}
## The largest number of one time keys this account can store.

proc generateOneTimeKeysRandomLength*(a: Account, number_of_keys: csize_t): csize_t {.importc: "olm_account_generate_one_time_keys_random_length".}
## The number of random bytes needed to generate a given number of new one
## time keys.

proc generateOneTimeKeys*(a: Account, numberOfKeys: csize_t, random: pointer, random_length: csize_t): csize_t {.importc: "olm_account_generate_one_time_keys".}
## Generates a number of new one time keys. If the total number of keys stored
## by this account exceeds max_number_of_one_time_keys() then the old keys are
## discarded. Returns olm_error() on error. If the number of random bytes is
## too small then olm_account_last_error() will be "NOT_ENOUGH_RANDOM".

proc generateFallbackKeyRandomLength*(a: Account): csize_t {.importc: "olm_account_generate_fallback_key_random_length".}
## The number of random bytes needed to generate a fallback key.

proc generateFallbackKey*(a: Account, random: pointer, random_length: csize_t): csize_t {.importc: "olm_account_generate_fallback_key".}
## Generates a new fallback key. Only one previous fallback key is
## stored. Returns olm_error() on error. If the number of random bytes is too
## small then olm_account_last_error() will be "NOT_ENOUGH_RANDOM".

proc fallbackKeyLength*(a: Account): csize_t {.importc: "olm_account_fallback_key_length".}
## The number of bytes needed to hold the fallback key as returned by
## olm_account_fallback_key.

proc fallbackKey*(a: Account, fallback_key: pointer, fallback_key_size: csize_t): csize_t {.importc: "olm_account_fallback_key".}

proc createOutboundSessionRandomLength*(s: Session): csize_t {.importc: "olm_create_outbound_session_random_length".}
## The number of random bytes needed to create an outbound session

proc createOutboundSession*(s: Session, a: Account, their_identity_key: pointer, their_identity_key_length: csize_t, their_one_time_key: pointer, their_one_time_key_length: csize_t, random: pointer, random_length: csize_t): csize_t {.importc: "olm_create_outbound_session".}
## Creates a new out-bound session for sending messages to a given identity_key
## and one_time_key. Returns olm_error() on failure. If the keys couldn't be
## decoded as base64 then olm_session_last_error() will be "INVALID_BASE64"
## If there weren't enough random bytes then olm_session_last_error() will
## be "NOT_ENOUGH_RANDOM".

proc createInboundSession*(s: Session, a: Account, one_time_key_message: pointer, message_length: csize_t): csize_t {.importc: "olm_create_inbound_session".}
## Create a new in-bound session for sending/receiving messages from an
## incoming PRE_KEY message. Returns olm_error() on failure. If the base64
## couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
## If the message was for an unsupported protocol version then
## olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
## couldn't be decoded then then olm_session_last_error() will be
## "BAD_MESSAGE_FORMAT". If the message refers to an unknown one time
## key then olm_session_last_error() will be "BAD_MESSAGE_KEY_ID".

proc createInboundSessionFrom*(s: Session, a: Account, their_identity_key: pointer, their_identity_key_length: csize_t, one_time_key_message: pointer, message_length: csize_t): csize_t {.importc: "olm_create_inbound_session_from".}
## Create a new in-bound session for sending/receiving messages from an
## incoming PRE_KEY message. Returns olm_error() on failure. If the base64
## couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
## If the message was for an unsupported protocol version then
## olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
## couldn't be decoded then then olm_session_last_error() will be
## "BAD_MESSAGE_FORMAT". If the message refers to an unknown one time
## key then olm_session_last_error() will be "BAD_MESSAGE_KEY_ID".

## The length of the buffer needed to return the id for this session.
proc idLength*(s: Session): csize_t {.importc: "olm_session_id_length".}

proc id*(s: Session, id: pointer, id_length: csize_t): csize_t {.importc: "olm_session_id".}
## An identifier for this session. Will be the same for both ends of the
## conversation. If the id buffer is too small then olm_session_last_error()
## will be "OUTPUT_BUFFER_TOO_SMALL".

proc hasReceivedMessage*(s: Session): cint {.importc: "olm_session_has_received_message".}

proc describe*(s: Session, buf: cstring, buflen: csize_t) {.importc: "olm_session_describe".}
## Write a null-terminated string describing the internal state of an olm
## session to the buffer provided for debugging and logging purposes.

proc matchesInboundSession*(s: Session, one_time_key_message: pointer, message_length: csize_t): csize_t {.importc: "olm_matches_inbound_session".}
## Checks if the PRE_KEY message is for this in-bound session. This can happen
## if multiple messages are sent to this account before this account sends a
## message in reply. The one_time_key_message buffer is destroyed. Returns 1 if
## the session matches. Returns 0 if the session does not match. Returns
## olm_error() on failure. If the base64 couldn't be decoded then
## olm_session_last_error will be "INVALID_BASE64".  If the message was for an
## unsupported protocol version then olm_session_last_error() will be
## "BAD_MESSAGE_VERSION". If the message couldn't be decoded then then
## olm_session_last_error() will be "BAD_MESSAGE_FORMAT".

proc matchesInboundSessionFrom*(s: Session, their_identity_key: pointer, their_identity_key_length: csize_t, one_time_key_message: pointer, message_length: csize_t): csize_t {.importc: "olm_matches_inbound_session_from".}
## Checks if the PRE_KEY message is for this in-bound session. This can happen
## if multiple messages are sent to this account before this account sends a
## message in reply. The one_time_key_message buffer is destroyed. Returns 1 if
## the session matches. Returns 0 if the session does not match. Returns
## olm_error() on failure. If the base64 couldn't be decoded then
## olm_session_last_error will be "INVALID_BASE64".  If the message was for an
## unsupported protocol version then olm_session_last_error() will be
## "BAD_MESSAGE_VERSION". If the message couldn't be decoded then then
## olm_session_last_error() will be "BAD_MESSAGE_FORMAT".

proc removeOneTimeKeys*(a: Account, s: Session): csize_t {.importc: "olm_remove_one_time_keys".}
## Removes the one time keys that the session used from the account. Returns
## olm_error() on failure. If the account doesn't have any matching one time
## keys then olm_account_last_error() will be "BAD_MESSAGE_KEY_ID".

proc encryptMessageType*(s: Session): csize_t {.importc: "olm_encrypt_message_type".}
## The type of the next message that olm_encrypt() will return. Returns
## OLM_MESSAGE_TYPE_PRE_KEY if the message will be a PRE_KEY message.
## Returns OLM_MESSAGE_TYPE_MESSAGE if the message will be a normal message.
## Returns olm_error on failure.

proc encryptRandomLength*(s: Session): csize_t {.importc: "olm_encrypt_random_length".}
## The number of random bytes needed to encrypt the next message.

proc encryptMessageLength*(s: Session, plaintext_length: csize_t): csize_t {.importc: "olm_encrypt_message_length".}
## The size of the next message in bytes for the given number of plain-text
## bytes.

proc encrypt*(s: Session, plaintext: pointer, plaintext_length: csize_t, random: pointer, random_length: csize_t, message: pointer, message_length: csize_t): csize_t {.importc: "olm_encrypt".}
## Encrypts a message using the session. Returns the length of the message in
## bytes on success. Writes the message as base64 into the message buffer.
## Returns olm_error() on failure. If the message buffer is too small then
## olm_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL". If there
## weren't enough random bytes then olm_session_last_error() will be
## "NOT_ENOUGH_RANDOM".

proc decryptMaxPlaintextLength*(s: Session, message_type: csize_t, message: pointer, message_length: csize_t): csize_t {.importc: "olm_decrypt_max_plaintext_length".}
## The maximum number of bytes of plain-text a given message could decode to.
## The actual size could be different due to padding. The input message buffer
## is destroyed. Returns olm_error() on failure. If the message base64
## couldn't be decoded then olm_session_last_error() will be
## "INVALID_BASE64". If the message is for an unsupported version of the
## protocol then olm_session_last_error() will be "BAD_MESSAGE_VERSION".
## If the message couldn't be decoded then olm_session_last_error() will be
## "BAD_MESSAGE_FORMAT".

proc decrypt*(s: Session, message_type: csize_t, message: pointer, message_length: csize_t, plaintext: pointer, max_plaintext_length: csize_t): csize_t {.importc: "olm_decrypt"}
## Decrypts a message using the session. The input message buffer is destroyed.
## Returns the length of the plain-text on success. Returns olm_error() on
## failure. If the plain-text buffer is smaller than
## olm_decrypt_max_plaintext_length() then olm_session_last_error()
## will be "OUTPUT_BUFFER_TOO_SMALL". If the base64 couldn't be decoded then
## olm_session_last_error() will be "INVALID_BASE64". If the message is for
## an unsupported version of the protocol then olm_session_last_error() will
## be "BAD_MESSAGE_VERSION". If the message couldn't be decoded then
## olm_session_last_error() will be BAD_MESSAGE_FORMAT".
## If the MAC on the message was invalid then olm_session_last_error() will
## be "BAD_MESSAGE_MAC".

proc sha256_length*(u: Utility): csize_t {.importc: "olm_sha256_length".}
## The length of the buffer needed to hold the SHA-256 hash.

proc sha256*(u: Utility, input: pointer, input_length: csize_t, output: pointer, output_length: csize_t): csize_t {.importc: "olm_sha256".}
## Calculates the SHA-256 hash of the input and encodes it as base64. If the
## output buffer is smaller than olm_sha256_length() then
## olm_utility_last_error() will be "OUTPUT_BUFFER_TOO_SMALL".

proc ed25519Verify*(u: Utility, key: pointer, key_length: csize_t, message: pointer, message_length: csize_t, signature: pointer, signature_length: csize_t): csize_t {.importc: "olm_ed25519_verify".}
## Verify an ed25519 signature. If the key was too small then
## olm_utility_last_error() will be "INVALID_BASE64". If the signature was invalid
## then olm_utility_last_error() will be "BAD_MESSAGE_MAC".
