load(
    "//:repositories.bzl",
    "googletest_repositories",
    "abseil_repositories",
    "protobuf_repositories",
    "bsslwrapper_repositories",
    "opensslcbs_repositories",
)

googletest_repositories()
abseil_repositories()
protobuf_repositories()
bsslwrapper_repositories()
opensslcbs_repositories()

new_local_repository(
    name = "openssl",
    path = "/usr/lib64/",
    build_file = "openssl.BUILD"
)

