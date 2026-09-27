cmake_minimum_required(VERSION 3.16)

# ============================================================================
# ChordAuditMatrixBench tests
# ============================================================================
# Unit tests owned by this repository. They link CoreLib (through
# ChordAuditMatrixLib) and no algorithm plugin, so they build and run wherever
# Bench builds: Bench CI configures with -DCAM_BUILD_TESTS=ON and runs ctest.
# Scenario tests that need the real DHTDynamic/SM9Static strategy targets are
# cross-submodule integration tests and live in the parent repository.
# ============================================================================

# The gtest helper ships with CoreLib: Bench's own 3rdparty/CoreLib checkout in
# standalone builds, the parent project's lib/ CoreLib when built in-tree
# (where the plugin-local CoreLib gitlink is intentionally left uninitialized).
if(CAM_STANDALONE)
    include(${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/CoreLib/.cmake/cam_add_gtest.cmake)
else()
    include(${CMAKE_SOURCE_DIR}/lib/.cmake/cam_add_gtest.cmake)
endif()

# Standalone Windows builds link CoreLib as a shared library; the loader looks
# for ChordAuditMatrixLib.dll next to the executable, and CoreLib's CAMDeploy
# puts that DLL in <build>/dist, so the test executables are deployed there
# too. (In-tree builds inherit the parent project's dist/ output directory.)
if(CAM_STANDALONE AND WIN32)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/dist")
endif()

set(CAM_BENCH_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../include)
set(CAM_BENCH_TEST_LABELS "ChordAuditMatrixBenchTests;scope:unit;purpose:regression")

cam_add_gtest(test_benchmark_metrics_collector_unit
    SOURCES test_metrics_collector_unit.cpp
    LINK_LIBS ChordAuditMatrixBench
    INCLUDE_DIRS ${CAM_BENCH_INCLUDE_DIRS}
    LABELS "${CAM_BENCH_TEST_LABELS}"
)

cam_add_gtest(test_benchmark_run_plan_unit
    SOURCES test_benchmark_run_plan_unit.cpp
    LINK_LIBS ChordAuditMatrixBench
    INCLUDE_DIRS ${CAM_BENCH_INCLUDE_DIRS}
    LABELS "${CAM_BENCH_TEST_LABELS};tech:fake"
)

cam_add_gtest(test_benchmark_timing_unit
    SOURCES test_benchmark_timing_unit.cpp
    LINK_LIBS ChordAuditMatrixBench
    INCLUDE_DIRS ${CAM_BENCH_INCLUDE_DIRS}
    LABELS "${CAM_BENCH_TEST_LABELS}"
)

cam_add_gtest(test_benchmark_report_unit
    SOURCES test_benchmark_report_unit.cpp
    LINK_LIBS ChordAuditMatrixBench
    INCLUDE_DIRS ${CAM_BENCH_INCLUDE_DIRS}
    LABELS "${CAM_BENCH_TEST_LABELS}"
)

cam_add_gtest(test_benchmark_scenario_defaults_unit
    SOURCES test_benchmark_scenario_defaults_unit.cpp
    LINK_LIBS ChordAuditMatrixBench
    INCLUDE_DIRS ${CAM_BENCH_INCLUDE_DIRS}
    LABELS "${CAM_BENCH_TEST_LABELS};tech:fake"
)
