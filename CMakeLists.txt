cmake_minimum_required(VERSION 3.7)
project(nitrokey_hotp_verification VERSION 1.4)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-guess-branch-probability -Wdate-time -frandom-seed=device.c -O0")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -gno-record-gcc-switches ")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fdebug-prefix-map=${CMAKE_CURRENT_BINARY_DIR}=heads")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}")
SET(CMAKE_EXE_LINKER_FLAGS  "-O1 -fsanitize=address")

set(GIT_VERSION_PLACEHOLDER "no-git-version")

OPTION(ADD_LOG "Print debug information to stdout" FALSE)
IF(NOT(ADD_LOG))
    message("Removing debug prints. Use ADD_LOG option to enable them.")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNDEBUG ")
ELSE ()
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -D_DEBUG")
    message("Debug prints enabled.")
ENDIF ()

OPTION(ADD_GIT_INFO "Add information about source code version from Git repository" TRUE)
IF(ADD_GIT_INFO)
    execute_process(
            COMMAND git describe --always HEAD
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_VERSION_PLACEHOLDER
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
ENDIF()


configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/version.c.in ${CMAKE_CURRENT_SOURCE_DIR}/src/version.c @ONLY)

set(SOURCE_FILES
        src/structs.h src/crc32.c src/crc32.h src/device.c src/device.h src/operations.c src/operations.h src/dev_commands.c src/dev_commands.h src/base32.c src/base32.h src/command_id.h src/random_data.c src/random_data.h src/min.c src/min.h src/settings.h src/version.h src/version.c src/return_codes.h src/return_codes.c src/ccid.h src/ccid.c src/tlv.c src/tlv.h src/operations_ccid.c src/operations_ccid.h src/utils.h src/utils.c
        )

add_library(nitrokey_hotp_verification_core STATIC ${SOURCE_FILES})

add_executable(hotp_verification src/main.c)


OPTION(USE_SYSTEM_HIDAPI "Link application against system HIDAPI library" FALSE)
IF(USE_SYSTEM_HIDAPI)
    find_package(PkgConfig)
    pkg_search_module(HIDAPI_LIBUSB REQUIRED hidapi)
    target_compile_options(hotp_verification PRIVATE ${HIDAPI_LIBUSB_CFLAGS})
    target_link_libraries(hotp_verification nitrokey_hotp_verification_core ${HIDAPI_LIBUSB_LDFLAGS})
ELSE()
    include_directories(hidapi)
    include_directories(hidapi/hidapi)
    include_directories(/usr/include/libusb-1.0)
    include_directories(/usr/include)
    add_library(hidapi-libusb STATIC hidapi/libusb/hid.c)
    target_link_libraries(hidapi-libusb usb-1.0)
    target_compile_definitions(hidapi-libusb PRIVATE NK_REMOVE_PTHREAD)
    target_link_libraries(hotp_verification nitrokey_hotp_verification_core hidapi-libusb)
ENDIF()

OPTION(COMPILE_TESTS "Compile Catch tests" FALSE)
IF(COMPILE_TESTS)
    include_directories(tests/catch2)
    add_library(catch STATIC tests/catch_main.cpp )
    SET(TESTS tests/test_hotp.cpp tests/test_aes_regen.cpp test_ccid.cpp)
    foreach(testsourcefile ${TESTS} )
        get_filename_component(testname ${testsourcefile} NAME_WE )
        add_executable(${testname} ${testsourcefile} )
        target_link_libraries(${testname} nitrokey_hotp_verification_core catch hidapi-libusb)
    #    SET_TARGET_PROPERTIES(${testname} PROPERTIES COMPILE_FLAGS ${COMPILE_FLAGS} )
    endforeach(testsourcefile)
ENDIF()
