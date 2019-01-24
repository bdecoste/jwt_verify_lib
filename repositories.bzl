load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

GOOGLETEST_COMMIT = "43863938377a9ea1399c0596269e0890b5c5515a"
GOOGLETEST_SHA256 = "7c8ece456ad588c30160429498e108e2df6f42a30888b3ec0abf5d9792d9d3a0"

def bsslwrapper_repositories(bind = True):
    http_archive(
        name = "bssl_wrapper",
        strip_prefix = "bssl_wrapper-34df33add45e1a02927fcf79b0bdd5899b7e2e36",
        url = "https://github.com/bdecoste/bssl_wrapper/archive/34df33add45e1a02927fcf79b0bdd5899b7e2e36.tar.gz",
        sha256 = "d9e500e1a8849c81e690966422baf66016a7ff85d044c210ad85644f62827158",
    )

    if bind:
        native.bind(
            name = "bssl_wrapper_lib",
            actual = "@bssl_wrapper//:bssl_wrapper_lib",
        )

def googletest_repositories(bind = True):
    http_archive(
        name = "googletest_git",
        build_file = "//:googletest.BUILD",
        strip_prefix = "googletest-" + GOOGLETEST_COMMIT,
        url = "https://github.com/google/googletest/archive/" + GOOGLETEST_COMMIT + ".tar.gz",
        sha256 = GOOGLETEST_SHA256,
    )

    if bind:
        native.bind(
            name = "googletest",
            actual = "@googletest_git//:googletest",
        )

        native.bind(
            name = "googletest_main",
            actual = "@googletest_git//:googletest_main",
        )

        native.bind(
            name = "googletest_prod",
            actual = "@googletest_git//:googletest_prod",
        )

ABSEIL_COMMIT = "cc8dcd307b76a575d2e3e0958a4fe4c7193c2f68"  # same as Envoy
ABSEIL_SHA256 = "e35082e88b9da04f4d68094c05ba112502a5063712f3021adfa465306d238c76"

def abseil_repositories(bind = True):
    http_archive(
        name = "com_google_absl",
        strip_prefix = "abseil-cpp-" + ABSEIL_COMMIT,
        url = "https://github.com/abseil/abseil-cpp/archive/" + ABSEIL_COMMIT + ".tar.gz",
        sha256 = ABSEIL_SHA256,
    )

    if bind:
        native.bind(
            name = "abseil_strings",
            actual = "@com_google_absl//absl/strings:strings",
        )
        native.bind(
            name = "abseil_time",
            actual = "@com_google_absl//absl/time:time",
        )
    _cctz_repositories(bind)

CCTZ_COMMIT = "e19879df3a14791b7d483c359c4acd6b2a1cd96b"
CCTZ_SHA256 = "35d2c6cf7ddef1cf7c1bb054bdf2e8d7778242f6d199591a834c14d224b80c39"

def _cctz_repositories(bind = True):
    http_archive(
        name = "com_googlesource_code_cctz",
        url = "https://github.com/google/cctz/archive/" + CCTZ_COMMIT + ".tar.gz",
        sha256 = CCTZ_SHA256,
    )

BAZEL_SKYLIB_RELEASE = "0.5.0"
BAZEL_SKYLIB_SHA256 = "b5f6abe419da897b7901f90cbab08af958b97a8f3575b0d3dd062ac7ce78541f"

def _bazel_skylib_repositories():
    http_archive(
        name = "bazel_skylib",
        sha256 = BAZEL_SKYLIB_SHA256,
        strip_prefix = "bazel-skylib-" + BAZEL_SKYLIB_RELEASE,
        url = "https://github.com/bazelbuild/bazel-skylib/archive/" + BAZEL_SKYLIB_RELEASE + ".tar.gz",
    )

PROTOBUF_COMMIT = "fa252ec2a54acb24ddc87d48fed1ecfd458445fd"
PROTOBUF_SHA256 = "3d610ac90f8fa16e12490088605c248b85fdaf23114ce4b3605cdf81f7823604"

def protobuf_repositories(bind = True):
    _bazel_skylib_repositories()
    http_archive(
        name = "com_google_protobuf",
        strip_prefix = "protobuf-" + PROTOBUF_COMMIT,
        url = "https://github.com/protocolbuffers/protobuf/archive/" + PROTOBUF_COMMIT + ".tar.gz",
        sha256 = PROTOBUF_SHA256,
    )

    if bind:
        native.bind(
            name = "protobuf",
            actual = "@com_google_protobuf//:protobuf",
        )
