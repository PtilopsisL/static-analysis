cmake_minimum_required(VERSION 3.20)
project(syscall_static_extractor LANGUAGES CXX)
find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_executable(syscall-extract src/main.cpp)
target_compile_features(syscall-extract PRIVATE cxx_std_17)
target_include_directories(syscall-extract SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS})
target_link_libraries(syscall-extract PRIVATE clang-cpp LLVM)

enable_testing()
add_test(
  NAME tests
  COMMAND ${Python3_EXECUTABLE} -m unittest discover -s ${CMAKE_SOURCE_DIR}/tests -v
)
set_tests_properties(tests PROPERTIES
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  ENVIRONMENT "SYSCALL_EXTRACTOR=$<TARGET_FILE:syscall-extract>"
)
