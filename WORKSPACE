load(
    "//:repositories.bzl",
    "boringssl_repositories",
    "googletest_repositories",
    "abseil_repositories",
    "protobuf_repositories",
)

boringssl_repositories()
googletest_repositories()
abseil_repositories()
protobuf_repositories()

new_local_repository(
    name = "openssl",
    path = "/usr/local/lib64",
    build_file = "openssl.BUILD"
)
