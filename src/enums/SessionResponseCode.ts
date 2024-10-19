enum SessionResponseErrorCodes {
    NOT_FOUND_ON_REQUEST,
    KEY_INVALID,
    SESSION_PARSE_ERROR,
    HASH_VALUES_ARE_NOT_EQUALS,
    EXPIRED_SESSION,
    USER_VALIDATE_ERROR,
}

export { SessionResponseErrorCodes as default };