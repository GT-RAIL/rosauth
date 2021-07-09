#define _SILENCE_TR1_NAMESPACE_DEPRECATION_WARNING
#include <fstream>
#include <gtest/gtest.h>
#include <openssl/sha.h>
#include <rclcpp/rclcpp.hpp>
#include <rosauth/srv/authentication.hpp>
#include <sstream>
#include <string>

using namespace std;

rclcpp::Node::SharedPtr node;
rclcpp::Client<rosauth::srv::Authentication>::SharedPtr client;

TEST(RosHashAuthentication, validAuthentication)
{
  string secret = "abcdefghijklmnop";
  string client_ip = "192.168.1.101";
  string dest_ip = "192.168.1.111";
  string rand = "xyzabc";
  auto now = node->now();
  string user_level = "admin";
  auto end = now + rclcpp::Duration(120, 0);

  // create the string to hash
  stringstream ss;
  ss << secret << client_ip << dest_ip << rand << now.nanoseconds() / 1000000000 << user_level << end.nanoseconds() / 1000000000;
  string local_hash = ss.str();
  unsigned char sha512_hash[SHA512_DIGEST_LENGTH];
  SHA512((unsigned char *)local_hash.c_str(), local_hash.length(), sha512_hash);

  // convert to a hex string to compare
  char hex[SHA512_DIGEST_LENGTH * 2 + 1];
  for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
    sprintf(&hex[i * 2], "%02x", sha512_hash[i]);

  // make the request
  auto request = make_shared<rosauth::srv::Authentication::Request>();
  request->mac = string(hex);
  request->client = client_ip;
  request->dest = dest_ip;
  request->rand = rand;
  request->t = now;
  request->level = user_level;
  request->end = end;

  auto result = client->async_send_request(request);
  EXPECT_TRUE(rclcpp::spin_until_future_complete(node, result) ==
    rclcpp::FutureReturnCode::SUCCESS);
  auto response = result.get();
  EXPECT_TRUE(response->authenticated);
}

// Run all the tests that were declared with TEST()
int main(int argc, char **argv)
{
  testing::InitGoogleTest(&argc, argv);

  // initialize ROS and the node
  rclcpp::init(argc, argv);
  node = make_shared<rclcpp::Node>("ros_hash_authentication_test");

  // setup the service client
  client = node->create_client<rosauth::srv::Authentication>("authenticate");
  client->wait_for_service();

  int rc = RUN_ALL_TESTS();

  client.reset();
  node.reset();
  rclcpp::shutdown();

  return rc;
}
