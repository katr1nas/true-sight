include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(crypto_tests
    crypto_tests.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/crypto/crypto.cpp
)

target_include_directories(crypto_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)

target_link_libraries(crypto_tests PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(crypto_tests)
