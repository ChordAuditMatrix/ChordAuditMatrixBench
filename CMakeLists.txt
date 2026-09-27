cmake_minimum_required(VERSION 3.16)
project(ChordAuditMatrixBench VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(CAM_STANDALONE "Build as standalone project (on) or as part of ChordAuditMatrix (off)" ON)
option(CAM_BUILD_TESTS "Build tests" OFF)
option(CAM_GENERATE_DOCS "Generate Doxygen documentation" OFF)

include(CheckCXXSourceCompiles)

# ==================== CoreLib Dependency ====================
# Standalone: statically compile-link CoreLib (and its transitive deps).
# In-tree: ChordAuditMatrixLib target is already provided by the parent project.
if(CAM_STANDALONE)
    # CoreLib's own test suite has its own CI; skip its test registration while
    # configuring it as a dependency and restore Bench's option afterwards.
    # (The parent project uses the same save/restore pattern for its lib/.)
    set(CAM_BENCH_BUILD_TESTS_SAVED "${CAM_BUILD_TESTS}")
    set(CAM_BUILD_TESTS OFF CACHE BOOL "CoreLib tests are in CoreLib CI" FORCE)
    add_subdirectory(3rdparty/CoreLib EXCLUDE_FROM_ALL)
    set(CAM_BUILD_TESTS "${CAM_BENCH_BUILD_TESTS_SAVED}" CACHE BOOL "Build tests" FORCE)
    unset(CAM_BENCH_BUILD_TESTS_SAVED)
endif()

# ==================== Sanitizer ====================
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=address -fno-omit-frame-pointer")
    check_cxx_source_compiles("
        #include <stdlib.h>
        int main() {
            volatile int *p = (int*)malloc(sizeof(int));
            *p = 42;
            free((void*)p);
            return 0;
        }
    " HAS_ASAN)
    if(HAS_ASAN)
        message(STATUS "Sanitizer enabled for Debug build")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
        set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=address")
    else()
        message(STATUS "Sanitizer not supported (compiler or linker)")
    endif()
endif()

# ==================== Windows Export ====================
if(WIN32)
    add_compile_definitions(NOMINMAX _WINSOCKAPI_ _CRT_SECURE_NO_WARNINGS)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# ==================== Benchmark Framework ====================
set(FRAMEWORK_SOURCE
    source/pdp_audit_scenario.cpp
    source/identity_verify_scenario.cpp
    source/dynamic_maintenance_scenario.cpp
    source/dynamic_maintenance_report.cpp
    source/benchmark_report.cpp
    source/benchmark_computation_strategy.cpp
)

add_library(${PROJECT_NAME} STATIC ${FRAMEWORK_SOURCE})

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME} PUBLIC
    ChordAuditMatrixLib spdlog::spdlog
)

# ==================== PDP Audit Benchmark Executable ====================
add_executable(Pdp${PROJECT_NAME} app/pdp_audit_benchmark_main.cpp)
target_link_libraries(Pdp${PROJECT_NAME} PRIVATE ${PROJECT_NAME} spdlog::spdlog)

# ==================== Identity Verification Benchmark Executable ====================
add_executable(Identity${PROJECT_NAME} app/identity_verify_benchmark_main.cpp)
target_link_libraries(Identity${PROJECT_NAME} PRIVATE ${PROJECT_NAME} spdlog::spdlog)

# ==================== Dynamic Maintenance Benchmark ====================
add_executable(DynamicMaintenance${PROJECT_NAME} app/dynamic_maintenance_benchmark_main.cpp)
target_link_libraries(DynamicMaintenance${PROJECT_NAME} PRIVATE ${PROJECT_NAME} spdlog::spdlog)

# ==================== Tests ====================
# Framework tests the Bench repository owns: MetricsCollector aggregation, the
# runner's BenchmarkRunPlan scheduling, the shared stage timer, the Report
# hierarchy and the Scenario defaults. They link CoreLib only — tests that need
# the real DHT/SM9 strategy plugins stay in the parent repository's integration
# suite, since Bench does not depend on those submodules.
if(CAM_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ==================== Deploy (in-tree only) ====================
if(NOT CAM_STANDALONE AND COMMAND cam_deploy_benchmark)
    cam_deploy_benchmark(Pdp${PROJECT_NAME})
    cam_deploy_benchmark(Identity${PROJECT_NAME})
    cam_deploy_benchmark(DynamicMaintenance${PROJECT_NAME})
endif()