cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(SealBenchmarks VERSION 0.1 LANGUAGES CXX)

set(SEAL_DIR ${SealBenchmarks_SOURCE_DIR}/seal)

message(STATUS "Setting up SEAL ...")
execute_process(
    COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
    OUTPUT_QUIET
    RESULT_VARIABLE result
    WORKING_DIRECTORY ${SEAL_DIR})
if(result)
    message(FATAL_ERROR "Failed to download SEAL (${result})!")
endif()

execute_process(COMMAND ${CMAKE_COMMAND} --build .
    OUTPUT_QUIET
    RESULT_VARIABLE result
    WORKING_DIRECTORY ${SEAL_DIR})
if(result)
    message(FATAL_ERROR "Failed to build SEAL (${result})!")
endif()

add_subdirectory(
  ${SEAL_DIR}/src
  ${SEAL_DIR}/build)

include_directories(
  ${SEAL_SRC_DIR})

include(FetchGoogletest.cmake)
include(FetchGooglebenchmark.cmake)

add_executable(seal_benchmarks seal_benchmarks.cpp )
target_link_libraries(seal_benchmarks PRIVATE gtest benchmark benchmark_main seal)
