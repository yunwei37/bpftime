# The header-only defaults helpers use only libc/libdl, so this test links
# neither frida-gum nor the transformer shared object.
if(${ENABLE_EBPF_VERIFIER} AND NOT TARGET Catch2)
    message(STATUS "Adding Catch2 by FetchContent for text_segment_transformer")
    Include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.4.0
    )
    FetchContent_MakeAvailable(Catch2)
endif()

add_library(bpftime_agent_defaults_fixture SHARED
    agent_defaults_fixture.cpp)
set_target_properties(bpftime_agent_defaults_fixture PROPERTIES
    CXX_STANDARD 20)

add_executable(bpftime_agent_transformer_defaults_tests
    test_agent_defaults.cpp)
add_dependencies(bpftime_agent_transformer_defaults_tests
    Catch2 bpftime_agent_defaults_fixture)
target_compile_definitions(bpftime_agent_transformer_defaults_tests PRIVATE
    BPFTIME_AGENT_DEFAULTS_FIXTURE_LIBRARY="$<TARGET_FILE:bpftime_agent_defaults_fixture>")
target_link_libraries(bpftime_agent_transformer_defaults_tests PRIVATE
    Catch2::Catch2WithMain ${CMAKE_DL_LIBS})
set_target_properties(bpftime_agent_transformer_defaults_tests PROPERTIES
    CXX_STANDARD 20)

add_test(NAME bpftime_agent_transformer_defaults_tests
    COMMAND bpftime_agent_transformer_defaults_tests)
