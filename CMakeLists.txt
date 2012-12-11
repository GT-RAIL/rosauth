cmake_minimum_required(VERSION 2.4.6)
include($ENV{ROS_ROOT}/core/rosbuild/rosbuild.cmake)

# Set the build type.  Options are:
#  Coverage       : w/ debug symbols, w/o optimization, w/ code-coverage
#  Debug          : w/ debug symbols, w/o optimization
#  Release        : w/o debug symbols, w/ optimization
#  RelWithDebInfo : w/ debug symbols, w/ optimization
#  MinSizeRel     : w/o debug symbols, w/ optimization, stripped binaries
set(ROS_BUILD_TYPE Release)

rosbuild_init()

#set the default path for built executables to the "bin" directory
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

#generate services
rosbuild_gensrv()

rosbuild_add_executable(ros_hash_authentication_test test/ros_hash_authentication_test.cpp)
rosbuild_add_gtest_build_flags(ros_hash_authentication_test)
target_link_libraries(ros_hash_authentication_test crypto)

rosbuild_add_rostest(test/ros_hash_authentication.test)

rosbuild_add_executable(ros_hash_authentication src/ros_hash_authentication.cpp)
target_link_libraries(ros_hash_authentication crypto)

rosbuild_make_distribution(0.0.1)
