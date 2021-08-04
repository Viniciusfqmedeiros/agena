cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

project(
  agena
  VERSION 0.1.0
  DESCRIPTION "A terminal-based Gemini client"
  LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)
set(CURSES_NEED_NCURSES TRUE)
set(AGENA_TGT agena)

if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "No build type specified, defaulting to Release")
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(GnuTLS REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Curses REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCRE2 REQUIRED libpcre2-posix libpcre2-8)

file(GLOB AGENA_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)

add_executable(
  ${AGENA_TGT} ${AGENA_SOURCES})

target_compile_options(${AGENA_TGT} PUBLIC -O0 -g -ggdb3)

target_compile_definitions(
  ${AGENA_TGT} PRIVATE
  GNUTLS_VERSION=${GNUTLS_VERSION})

target_include_directories(
  ${AGENA_TGT} PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${PCRE2_INCLUDE_DIR}
  ${GNUTLS_INCLUDE_DIR}
  ${SQLite3_INCLUDE_DIRS}
  ${CURSES_INCLUDE_DIRS})

target_link_libraries(
  ${AGENA_TGT} PRIVATE
  ${PCRE2_LIBRARIES}
  ${GNUTLS_LIBRARIES}
  ${SQLite3_LIBRARIES}
  ${CURSES_LIBRARIES})

