load(
    "//:repositories.bzl",
    "googletest_repositories",
    "abseil_repositories",
    "protobuf_repositories",
#    "bsslwrapper_repositories",
)

#bsslwrapper_repositories()
googletest_repositories()
abseil_repositories()
protobuf_repositories()

http_archive(
    name = "bssl_wrapper",
    sha256 = "c7d9d2a48c0e06f343a1ccdc1453f4ecceeb71223c5650f6a84c40f4e83b793c",
    strip_prefix = "bssl_wrapper-0.2",
    url = "https://github.com/bdecoste/bssl_wrapper/archive/0.2.tar.gz",
)

new_local_repository(
    name = "openssl",
    path = "/usr/local/lib64",
    build_file = "openssl.BUILD"
)
