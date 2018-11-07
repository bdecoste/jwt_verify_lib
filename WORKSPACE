load(
    "//:repositories.bzl",
    "googletest_repositories",
    "rapidjson_repositories",
    "abseil_repositories",
)

googletest_repositories()
rapidjson_repositories()
abseil_repositories()

new_local_repository(
    name = "openssl",
    path = "/usr/local/lib64",
    build_file = "openssl.BUILD"
)
