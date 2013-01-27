cmake_minimum_required(VERSION 2.8.3)
project(rosauth)

## Find catkin macros and libraries
## if COMPONENTS list like find_package(catkin REQUIRED COMPONENTS xyz)
## is used, also find other catkin packages
find_package(catkin REQUIRED COMPONENTS roscpp message_generation rostest)

#######################################
## Declare ROS messages and services ##
#######################################

## Generate services in the 'srv' folder
add_service_files(
  FILES
  Authentication.srv
)

## Generate added messages and services with any dependencies listed here
generate_messages(
  DEPENDENCIES
)

###################################################
## Declare things to be passed to other projects ##
###################################################

## LIBRARIES: libraries you create in this project that dependent projects also need
## CATKIN_DEPENDS: catkin_packages dependent projects also need
## DEPENDS: system dependencies of this project that dependent projects also need
catkin_package()

###########
## Build ##
###########

## Declare a cpp executable
add_executable(ros_hash_authentication src/ros_hash_authentication.cpp)

## Specify libraries to link a library or executable target against
target_link_libraries(ros_hash_authentication
  ${catkin_LIBRARIES} crypto
)

add_dependencies(ros_hash_authentication ${PROJECT_NAME}_gencpp)

#############
## Install ##
#############

## Mark executables and/or libraries for installation
install(TARGETS ros_hash_authentication
  RUNTIME DESTINATION ${CATKIN_PACKAGE_BIN_DESTINATION}
)

#############
## Testing ##
#############

## Add gtest based cpp test target and link libraries
catkin_add_gtest(ros_hash_authentication_test test/ros_hash_authentication_test.cpp)
target_link_libraries(ros_hash_authentication_test ${catkin_LIBRARIES} crypto)
add_rostest(test/ros_hash_authentication.test)
