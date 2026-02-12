include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.14.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(entropy_tests
    test_main.cpp
    unit/test_pow_verifier.cpp
    unit/test_input_validator.cpp
    unit/test_connection_manager.cpp
    integration/test_http_handlers.cpp
    integration/test_identity_handler.cpp
    unit/test_traffic_normalizer.cpp
    security/test_vulnerability_vectors.cpp
    security/test_dos_protection.cpp
    security/test_security_audit.cpp
    integration/test_full_flow.cpp
    advanced/test_concurrency.cpp
    advanced/test_timing_resistance.cpp
    advanced/test_fuzzing.cpp
    advanced/test_resource_lifecycle.cpp
    advanced/test_network_faults.cpp
    advanced/test_benchmarks.cpp
    advanced/test_extreme_backpressure.cpp
    advanced/test_logging_audit.cpp
    advanced/test_stateful_fuzzing.cpp
    advanced/test_soak_stability.cpp
    security/test_crypto_extremes.cpp
    security/test_admin_security.cpp
    advanced/test_network_chaos.cpp
)

target_link_libraries(entropy_tests
    PRIVATE
    GTest::gtest
    GTest::gmock
    server_core
    OpenSSL::Crypto
)

target_include_directories(entropy_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include/handlers
)

# Enable discover tests
include(GoogleTest)
gtest_discover_tests(entropy_tests)
