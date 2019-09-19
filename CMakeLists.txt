cmake_minimum_required(VERSION 3.5)
project(rosauth)

find_package(ament_cmake_ros REQUIRED)
find_package(builtin_interfaces REQUIRED)
find_package(rclcpp REQUIRED)
find_package(rosidl_default_generators REQUIRED)
find_package(OpenSSL REQUIRED)

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 14)
endif()

rosidl_generate_interfaces(${PROJECT_NAME}
  srv/Authentication.srv
  DEPENDENCIES builtin_interfaces
)

add_executable(ros_mac_authentication src/ros_mac_authentication.cpp)
add_dependencies(ros_mac_authentication ${PROJECT_NAME})
ament_target_dependencies(ros_mac_authentication rclcpp)
rosidl_target_interfaces(
  ros_mac_authentication ${PROJECT_NAME} "rosidl_typesupport_cpp")
target_link_libraries(ros_mac_authentication crypto)

## Specify libraries to link a library or executable target against
target_link_libraries(ros_mac_authentication ${catkin_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)

ament_export_dependencies(rosidl_default_runtime)

ament_package()

install(TARGETS ros_mac_authentication
  RUNTIME DESTINATION lib/${PROJECT_NAME}
)

#############
## Testing ##
#############

if(BUILD_TESTING)
  find_package(ament_cmake_gtest REQUIRED)
  ## Add gtest based cpp test target and link libraries
  ament_add_gtest_executable(ros_mac_authentication_test test/ros_mac_authentication_test.cpp)
  rosidl_target_interfaces(ros_mac_authentication_test
    ${PROJECT_NAME} "rosidl_typesupport_cpp")
  ament_target_dependencies(ros_mac_authentication_test builtin_interfaces rclcpp)
  target_link_libraries(ros_mac_authentication_test crypto dl pthread)

  # TODO replace parameter file with just passing the parameter once that is supported
  set(PARAMETERS_YAML_FILE "${CMAKE_CURRENT_BINARY_DIR}/secret.yaml")
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/test/secret.yaml.in"
    "${PARAMETERS_YAML_FILE}"
    @ONLY)

  set(ROS_MAC_AUTHENTICATION_EXECUTABLE $<TARGET_FILE:ros_mac_authentication>)
  set(ROS_MAC_AUTHENTICATION_TEST_EXECUTABLE $<TARGET_FILE:ros_mac_authentication_test>)
  set(generated_test_file "${CMAKE_CURRENT_BINARY_DIR}/ros_mac_authentication_test")
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/test/ros_mac_authentication_test.py.in"
    "${generated_test_file}.py.genexp"
    @ONLY)
  file(GENERATE
    OUTPUT "${generated_test_file}_$<CONFIG>.py"
    INPUT "${generated_test_file}.py.genexp"
  )
  ament_add_test(tests
    COMMAND "${generated_test_file}_$<CONFIG>.py"
    GENERATE_RESULT_FOR_RETURN_CODE_ZERO)
endif()
