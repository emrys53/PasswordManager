include(doctest)

# small function to add and register tests in the subdirectories
function(addTest testName_ libName_)
    add_executable(${testName_} ${testName_}.cpp)
    target_link_libraries(${testName_} PRIVATE doctest::doctest lib::${libName_} pthread)
    target_compile_features(${testName_} PUBLIC cxx_std_20)
    doctest_discover_tests(${testName_} TEST_PREFIX "${libName_}_")
endfunction(addTest)

add_subdirectory(sha256)
add_subdirectory(aes)
add_subdirectory(util)
add_subdirectory(hmac)
