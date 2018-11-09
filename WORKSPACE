load(
    "//:repositories.bzl",
    "googletest_repositories",
    "rapidjson_repositories",
    "abseil_repositories",
#    "bsslwrapper_repositories",
)

#bsslwrapper_repositories()
googletest_repositories()
rapidjson_repositories()
abseil_repositories()

http_archive(
    name = "bssl_wrapper",
    sha256 = "5d010d6fe3e1ab5b2891e6d74b0849d4184cdd0302493a3c96f28cbe69d4ecd0",
    strip_prefix = "bssl_wrapper-0.3",
    url = "https://github.com/bdecoste/bssl_wrapper/archive/0.3.tar.gz",
)

new_local_repository(
    name = "openssl",
    path = "/usr/local/lib64",
    build_file = "openssl.BUILD"
)
