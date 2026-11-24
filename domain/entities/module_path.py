DEFAULT_MODULE_DEPTH = 2
ROOT_MODULE = "(root)"
FEATURE_PREFIXES = ("lib/features/", "lib/apps/")
FEATURE_MODULE_DEPTH = 3
PATH_SEPARATOR = "/"


def resolve_module(path: str, depth: int = DEFAULT_MODULE_DEPTH) -> str:
    segments = path.split(PATH_SEPARATOR)
    if path.startswith(FEATURE_PREFIXES) and len(segments) > FEATURE_MODULE_DEPTH:
        return PATH_SEPARATOR.join(segments[:FEATURE_MODULE_DEPTH])
    directories = segments[:-1]
    if not directories:
        return ROOT_MODULE
    return PATH_SEPARATOR.join(directories[:depth])
