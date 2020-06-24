cmake_minimum_required(VERSION 3.7)
project(nitrokey_hotp_verification VERSION 1.2)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-guess-branch-probability -Wdate-time -frandom-seed=device.c -O0")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -gno-record-gcc-switches -DNDEBUG")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fdebug-prefix-map=${CMAKE_CURRENT_BINARY_DIR}=heads")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -D_DEBUG")
SET(CMAKE_EXE_LINKER_FLAGS  "-O0")

set(GIT_VERSION_PLACEHOLDER "no-git-version")

OPTION(ADD_GIT_INFO "Add information about source code version from Git repository" TRUE)
IF(ADD_GIT_INFO)
    execute_process(
            COMMAND git describe --always HEAD
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_VERSION_PLACEHOLDER
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
ENDIF()


configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.c.in ${CMAKE_CURRENT_SOURCE_DIR}/version.c @ONLY)

set(SOURCE_FILES structs.h crc32.c crc32.h device.c device.h operations.c operations.h
        dev_commands.c dev_commands.h
        base32.c base32.h command_id.h random_data.c random_data.h
        min.c min.h settings.h version.h version.c return_codes.h return_codes.c)

add_library(nitrokey_hotp_verification_core STATIC ${SOURCE_FILES})

add_executable(nitrokey_hotp_verification main.c)
add_executable(libremkey_hotp_verification main.c)


OPTION(USE_SYSTEM_HIDAPI "Link application against system HIDAPI library" FALSE)
IF(USE_SYSTEM_HIDAPI)
    find_package(PkgConfig)
    pkg_search_module(HIDAPI_LIBUSB REQUIRED hidapi-libusb)
    target_compile_options(nitrokey_hotp_verification PRIVATE ${HIDAPI_LIBUSB_CFLAGS})
    target_compile_options(libremkey_hotp_verification PRIVATE ${HIDAPI_LIBUSB_CFLAGS})
    target_link_libraries(nitrokey_hotp_verification nitrokey_hotp_verification_core ${HIDAPI_LIBUSB_LDFLAGS})
    target_link_libraries(libremkey_hotp_verification nitrokey_hotp_verification_core ${HIDAPI_LIBUSB_LDFLAGS})
ELSE()
    include_directories(hidapi/hidapi)
    include_directories(/usr/include/libusb-1.0)
    add_library(hidapi-libusb STATIC hidapi/libusb/hid.c)
    target_link_libraries(hidapi-libusb usb-1.0)
    target_compile_definitions(hidapi-libusb PRIVATE NK_REMOVE_PTHREAD)
    target_link_libraries(nitrokey_hotp_verification nitrokey_hotp_verification_core hidapi-libusb)
    target_link_libraries(libremkey_hotp_verification nitrokey_hotp_verification_core hidapi-libusb)
ENDIF()

OPTION(COMPILE_TESTS "Compile Catch tests" FALSE)
IF(COMPILE_TESTS)
    include_directories(tests/catch2)
    add_library(catch STATIC tests/catch_main.cpp )
    SET(TESTS tests/test_hotp.cpp tests/test_aes_regen.cpp)
    foreach(testsourcefile ${TESTS} )
        get_filename_component(testname ${testsourcefile} NAME_WE )
        add_executable(${testname} ${testsourcefile} )
        target_link_libraries(${testname} nitrokey_hotp_verification_core catch hidapi-libusb)
    #    SET_TARGET_PROPERTIES(${testname} PROPERTIES COMPILE_FLAGS ${COMPILE_FLAGS} )
    endforeach(testsourcefile)
ENDIF()
