licenses(["notice"])  # Apache 2

package(default_visibility = ["//visibility:public"])

exports_files(["LICENSE"])

cc_library(
    name = "jwt_verify_lib",
    srcs = [
        "src/check_audience.cc",
        "src/jwks.cc",
        "src/jwt.cc",
        "src/status.cc",
        "src/struct_utils.h",
        "src/verify.cc",
    ],
    hdrs = [
        "jwt_verify_lib/check_audience.h",
        "jwt_verify_lib/jwks.h",
        "jwt_verify_lib/jwt.h",
        "jwt_verify_lib/status.h",
        "jwt_verify_lib/verify.h",
    ],
    deps = [
        ":cbs_lib",
        "//external:abseil_strings",
        "//external:abseil_time",
        "//external:protobuf",
        "//external:bssl_wrapper",
        "@openssl//:openssl-lib",
    ],
)

cc_library(
    name = "cbs_lib",
    srcs = [
        "src/cbs.cc",
    ],
    hdrs = [
        "jwt_verify_lib/cbs.h",
    ],
    deps = [
        "//external:bssl_wrapper",
        "@openssl//:openssl-lib",
    ],
)

cc_test(
    name = "check_audience_test",
    srcs = [
        "src/check_audience_test.cc",
    ],
    linkopts = [
        "-lm",
        "-lpthread",
    ],
    linkstatic = 1,
    deps = [
        ":jwt_verify_lib",
        "//external:googletest_main",
    ],
)

cc_test(
    name = "jwt_test",
    srcs = [
        "src/jwt_test.cc",
    ],
    linkopts = [
        "-lm",
        "-lpthread",
    ],
    linkstatic = 1,
    deps = [
        ":jwt_verify_lib",
        "//external:googletest_main",
    ],
)

cc_test(
    name = "jwks_test",
    srcs = [
        "src/jwks_test.cc",
    ],
    linkopts = [
        "-lm",
        "-lpthread",
    ],
    linkstatic = 1,
    deps = [
        ":jwt_verify_lib",
        "//external:googletest_main",
    ],
)

cc_test(
    name = "verify_pem_test",
    srcs = [
        "src/test_common.h",
        "src/verify_pem_test.cc",
    ],
    linkopts = [
        "-lm",
        "-lpthread",
    ],
    linkstatic = 1,
    deps = [
        ":jwt_verify_lib",
        "//external:googletest_main",
    ],
)

cc_test(
    name = "verify_audiences_test",
    srcs = [
        "src/test_common.h",
        "src/verify_audiences_test.cc",
    ],
    linkopts = [
        "-lm",
        "-lpthread",
    ],
    linkstatic = 1,
    deps = [
        ":jwt_verify_lib",
        "//external:googletest_main",
    ],
)

cc_test(
    name = "verify_time_test",
    srcs = [
        "src/test_common.h",
        "src/verify_time_test.cc",
    ],
    linkopts = [
        "-lm",
        "-lpthread",
    ],
    linkstatic = 1,
    deps = [
        ":jwt_verify_lib",
        "//external:googletest_main",
    ],
)

cc_test(
    name = "verify_jwk_rsa_test",
    srcs = [
        "src/test_common.h",
        "src/verify_jwk_rsa_test.cc",
    ],
    linkopts = [
        "-lm",
        "-lpthread",
    ],
    linkstatic = 1,
    deps = [
        ":jwt_verify_lib",
        "//external:googletest_main",
    ],
)

cc_test(
    name = "verify_jwk_ec_test",
    srcs = [
        "src/test_common.h",
        "src/verify_jwk_ec_test.cc",
    ],
    linkopts = [
        "-lm",
        "-lpthread",
    ],
    linkstatic = 1,
    deps = [
        ":jwt_verify_lib",
        "//external:googletest_main",
    ],
)
