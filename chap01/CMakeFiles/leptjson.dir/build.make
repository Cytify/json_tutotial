# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/axaxaxa/code/vscode_workspace/json_tutotial/chap01

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/axaxaxa/code/vscode_workspace/json_tutotial/chap01

# Include any dependencies generated for this target.
include CMakeFiles/leptjson.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/leptjson.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/leptjson.dir/flags.make

CMakeFiles/leptjson.dir/lept_json.c.o: CMakeFiles/leptjson.dir/flags.make
CMakeFiles/leptjson.dir/lept_json.c.o: lept_json.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/axaxaxa/code/vscode_workspace/json_tutotial/chap01/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/leptjson.dir/lept_json.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/leptjson.dir/lept_json.c.o   -c /home/axaxaxa/code/vscode_workspace/json_tutotial/chap01/lept_json.c

CMakeFiles/leptjson.dir/lept_json.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/leptjson.dir/lept_json.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/axaxaxa/code/vscode_workspace/json_tutotial/chap01/lept_json.c > CMakeFiles/leptjson.dir/lept_json.c.i

CMakeFiles/leptjson.dir/lept_json.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/leptjson.dir/lept_json.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/axaxaxa/code/vscode_workspace/json_tutotial/chap01/lept_json.c -o CMakeFiles/leptjson.dir/lept_json.c.s

# Object files for target leptjson
leptjson_OBJECTS = \
"CMakeFiles/leptjson.dir/lept_json.c.o"

# External object files for target leptjson
leptjson_EXTERNAL_OBJECTS =

libleptjson.a: CMakeFiles/leptjson.dir/lept_json.c.o
libleptjson.a: CMakeFiles/leptjson.dir/build.make
libleptjson.a: CMakeFiles/leptjson.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/axaxaxa/code/vscode_workspace/json_tutotial/chap01/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C static library libleptjson.a"
	$(CMAKE_COMMAND) -P CMakeFiles/leptjson.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/leptjson.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/leptjson.dir/build: libleptjson.a

.PHONY : CMakeFiles/leptjson.dir/build

CMakeFiles/leptjson.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/leptjson.dir/cmake_clean.cmake
.PHONY : CMakeFiles/leptjson.dir/clean

CMakeFiles/leptjson.dir/depend:
	cd /home/axaxaxa/code/vscode_workspace/json_tutotial/chap01 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/axaxaxa/code/vscode_workspace/json_tutotial/chap01 /home/axaxaxa/code/vscode_workspace/json_tutotial/chap01 /home/axaxaxa/code/vscode_workspace/json_tutotial/chap01 /home/axaxaxa/code/vscode_workspace/json_tutotial/chap01 /home/axaxaxa/code/vscode_workspace/json_tutotial/chap01/CMakeFiles/leptjson.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/leptjson.dir/depend
