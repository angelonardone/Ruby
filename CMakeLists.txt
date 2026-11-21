cmake_minimum_required(VERSION 3.16)
if(DEFINED ESP_PLATFORM AND ESP_PLATFORM EQUAL 1)
    set(EXTRA_COMPONENT_DIRS bootloader_components/bootloader_support)
    # Ruby: the firmware version is the nearest ruby-* tag (upstream Jade tags are ignored, so merging Jade does not
    # change it), e.g. ruby-1.0.0 or ruby-1.0.0-3-gabcdef12 for a development build, plus -dirty when a tracked source
    # file differs from the commit.  The sdkconfig* and Dockerfile* files are left out of that check: the Docker
    # builds replace or drop them.  Without git (or without a ruby-* tag) ESP-IDF's own default is used.
    find_package(Git QUIET)
    if(GIT_FOUND)
        execute_process(COMMAND ${GIT_EXECUTABLE} describe --tags --match "ruby-*"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            OUTPUT_VARIABLE RUBY_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
        if(RUBY_VERSION)
            execute_process(COMMAND ${GIT_EXECUTABLE} status --porcelain --untracked-files=no --
                    . ":(exclude)sdkconfig*" ":(exclude)Dockerfile*"
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                OUTPUT_VARIABLE RUBY_DIRTY OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
            if(RUBY_DIRTY)
                string(APPEND RUBY_VERSION "-dirty")
            endif()
            set(PROJECT_VER "${RUBY_VERSION}")
        endif()
    endif()
    include($ENV{IDF_PATH}/tools/cmake/project.cmake)
    idf_build_set_property(DEPENDENCIES_LOCK dependencies.lock.${IDF_TARGET})
    project(jade)
    idf_component_get_property(cbor_component espressif__cbor COMPONENT_LIB)
    target_compile_definitions(${cbor_component} PRIVATE CBOR_PARSER_MAX_RECURSIONS=20)
else()
    add_subdirectory(libjade)
endif()
