#include <fstream>
#include <gtest/gtest.h>
#include <openssl/sha.h>
#include <ros/ros.h>
#include <rosauth/Authentication.h>
#include <sstream>
#include <string>

using namespace std;
using namespace ros;

ServiceClient client;

TEST(RosHashAuthentication, validAuthentication)
{
  string secret = "abcdefghijklmnop";
  string client_ip = "192.168.1.101";
  string dest_ip = "192.168.1.111";
  string rand = "xyzabc";
  Time now = Time::now();
  string user_level = "admin";
  Time end = Time::now();
  end.sec += 120;

  // create the string to hash
  stringstream ss;
  ss << secret << client_ip << dest_ip << rand << now.toNSec() << user_level << end.toNSec();
  string local_hash = ss.str();
  unsigned char sha1_hash[SHA_DIGEST_LENGTH];
  SHA1((unsigned char *)local_hash.c_str(), local_hash.length(), sha1_hash);

  // convert to a hex string to compare
  char hex[SHA_DIGEST_LENGTH * 2];
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    sprintf(&hex[i * 2], "%02x", sha1_hash[i]);

  // make the request
  rosauth::Authentication srv;
  srv.request.mac = string(hex);
  srv.request.client = client_ip;
  srv.request.dest = dest_ip;
  srv.request.rand = rand;
  srv.request.t = now;
  srv.request.level = user_level;
  srv.request.end = end;

  EXPECT_TRUE(client.call(srv));
  EXPECT_TRUE(srv.response.authenticated);
}

TEST(RosHashAuthentication, invalidSecret)
{
  string secret = "abcdefghijklmnoq";
  string client_ip = "192.168.1.101";
  string dest_ip = "192.168.1.111";
  string rand = "xyzabc";
  Time now = Time::now();
  string user_level = "admin";
  Time end = Time::now();
  end.sec += 120;

  // create the string to hash
  stringstream ss;
  ss << secret << client_ip << dest_ip << rand << now.toNSec() << user_level << end.toNSec();
  string local_hash = ss.str();
  unsigned char sha1_hash[SHA_DIGEST_LENGTH];
  SHA1((unsigned char *)local_hash.c_str(), local_hash.length(), sha1_hash);

  // convert to a hex string to compare
  char hex[SHA_DIGEST_LENGTH * 2];
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    sprintf(&hex[i * 2], "%02x", sha1_hash[i]);

  // make the request
  rosauth::Authentication srv;
  srv.request.mac = string(hex);
  srv.request.client = client_ip;
  srv.request.dest = dest_ip;
  srv.request.rand = rand;
  srv.request.t = now;
  srv.request.level = user_level;
  srv.request.end = end;

  EXPECT_TRUE(client.call(srv));
  EXPECT_FALSE(srv.response.authenticated);
}

TEST(RosHashAuthentication, invalidClientIP)
{
  string secret = "abcdefghijklmnoq";
  string client_ip = "192.168.1.101";
  string dest_ip = "192.168.1.111";
  string rand = "xyzabc";
  Time now = Time::now();
  string user_level = "admin";
  Time end = Time::now();
  end.sec += 120;

  // create the string to hash
  stringstream ss;
  ss << secret << "192.168.1.102" << dest_ip << rand << now.toNSec() << user_level << end.toNSec();
  string local_hash = ss.str();
  unsigned char sha1_hash[SHA_DIGEST_LENGTH];
  SHA1((unsigned char *)local_hash.c_str(), local_hash.length(), sha1_hash);

  // convert to a hex string to compare
  char hex[SHA_DIGEST_LENGTH * 2];
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    sprintf(&hex[i * 2], "%02x", sha1_hash[i]);

  // make the request
  rosauth::Authentication srv;
  srv.request.mac = string(hex);
  srv.request.client = client_ip;
  srv.request.dest = dest_ip;
  srv.request.rand = rand;
  srv.request.t = now;
  srv.request.level = user_level;
  srv.request.end = end;

  EXPECT_TRUE(client.call(srv));
  EXPECT_FALSE(srv.response.authenticated);
}

TEST(RosHashAuthentication, invalidDestinationIP)
{
  string secret = "abcdefghijklmnoq";
  string client_ip = "192.168.1.101";
  string dest_ip = "192.168.1.111";
  string rand = "xyzabc";
  Time now = Time::now();
  string user_level = "admin";
  Time end = Time::now();
  end.sec += 120;

  // create the string to hash
  stringstream ss;
  ss << secret << client_ip << "192.168.1.101" << rand << now.toNSec() << user_level << end.toNSec();
  string local_hash = ss.str();
  unsigned char sha1_hash[SHA_DIGEST_LENGTH];
  SHA1((unsigned char *)local_hash.c_str(), local_hash.length(), sha1_hash);

  // convert to a hex string to compare
  char hex[SHA_DIGEST_LENGTH * 2];
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    sprintf(&hex[i * 2], "%02x", sha1_hash[i]);

  // make the request
  rosauth::Authentication srv;
  srv.request.mac = string(hex);
  srv.request.client = client_ip;
  srv.request.dest = dest_ip;
  srv.request.rand = rand;
  srv.request.t = now;
  srv.request.level = user_level;
  srv.request.end = end;

  EXPECT_TRUE(client.call(srv));
  EXPECT_FALSE(srv.response.authenticated);
}

TEST(RosHashAuthentication, invalidRand)
{
  string secret = "abcdefghijklmnoq";
  string client_ip = "192.168.1.101";
  string dest_ip = "192.168.1.111";
  string rand = "xyzabc";
  Time now = Time::now();
  string user_level = "admin";
  Time end = Time::now();
  end.sec += 120;

  // create the string to hash
  stringstream ss;
  ss << secret << client_ip << dest_ip << "123456" << now.toNSec() << user_level << end.toNSec();
  string local_hash = ss.str();
  unsigned char sha1_hash[SHA_DIGEST_LENGTH];
  SHA1((unsigned char *)local_hash.c_str(), local_hash.length(), sha1_hash);

  // convert to a hex string to compare
  char hex[SHA_DIGEST_LENGTH * 2];
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    sprintf(&hex[i * 2], "%02x", sha1_hash[i]);

  // make the request
  rosauth::Authentication srv;
  srv.request.mac = string(hex);
  srv.request.client = client_ip;
  srv.request.dest = dest_ip;
  srv.request.rand = rand;
  srv.request.t = now;
  srv.request.level = user_level;
  srv.request.end = end;

  EXPECT_TRUE(client.call(srv));
  EXPECT_FALSE(srv.response.authenticated);
}

TEST(RosHashAuthentication, oldTime)
{
  string secret = "abcdefghijklmnoq";
  string client_ip = "192.168.1.101";
  string dest_ip = "192.168.1.111";
  string rand = "xyzabc";
  Time now = Time::now();
  now.sec -= 6;
  string user_level = "admin";
  Time end = Time::now();
  end.sec += 120;

  // create the string to hash
  stringstream ss;
  ss << secret << client_ip << dest_ip << rand << now.toNSec() << user_level << end.toNSec();
  string local_hash = ss.str();
  unsigned char sha1_hash[SHA_DIGEST_LENGTH];
  SHA1((unsigned char *)local_hash.c_str(), local_hash.length(), sha1_hash);

  // convert to a hex string to compare
  char hex[SHA_DIGEST_LENGTH * 2];
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    sprintf(&hex[i * 2], "%02x", sha1_hash[i]);

  // make the request
  rosauth::Authentication srv;
  srv.request.mac = string(hex);
  srv.request.client = client_ip;
  srv.request.dest = dest_ip;
  srv.request.rand = rand;
  srv.request.t = now;
  srv.request.level = user_level;
  srv.request.end = end;

  EXPECT_TRUE(client.call(srv));
  EXPECT_FALSE(srv.response.authenticated);
}

TEST(RosHashAuthentication, newTime)
{
  string secret = "abcdefghijklmnoq";
  string client_ip = "192.168.1.101";
  string dest_ip = "192.168.1.111";
  string rand = "xyzabc";
  Time now = Time::now();
  now.sec += 6;
  string user_level = "admin";
  Time end = Time::now();
  end.sec += 120;

  // create the string to hash
  stringstream ss;
  ss << secret << client_ip << dest_ip << rand << now.toNSec() << user_level << end.toNSec();
  string local_hash = ss.str();
  unsigned char sha1_hash[SHA_DIGEST_LENGTH];
  SHA1((unsigned char *)local_hash.c_str(), local_hash.length(), sha1_hash);

  // convert to a hex string to compare
  char hex[SHA_DIGEST_LENGTH * 2];
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    sprintf(&hex[i * 2], "%02x", sha1_hash[i]);

  // make the request
  rosauth::Authentication srv;
  srv.request.mac = string(hex);
  srv.request.client = client_ip;
  srv.request.dest = dest_ip;
  srv.request.rand = rand;
  srv.request.t = now;
  srv.request.level = user_level;
  srv.request.end = end;

  EXPECT_TRUE(client.call(srv));
  EXPECT_FALSE(srv.response.authenticated);
}

TEST(RosHashAuthentication, invalidTime)
{
  string secret = "abcdefghijklmnoq";
  string client_ip = "192.168.1.101";
  string dest_ip = "192.168.1.111";
  string rand = "xyzabc";
  Time now = Time::now();
  Time now_invalid = Time::now();
  now_invalid.sec += 120;
  string user_level = "admin";
  Time end = Time::now();
  end.sec += 120;

  // create the string to hash
  stringstream ss;
  ss << secret << client_ip << dest_ip << rand << now_invalid.toNSec() << user_level << end.toNSec();
  string local_hash = ss.str();
  unsigned char sha1_hash[SHA_DIGEST_LENGTH];
  SHA1((unsigned char *)local_hash.c_str(), local_hash.length(), sha1_hash);

  // convert to a hex string to compare
  char hex[SHA_DIGEST_LENGTH * 2];
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    sprintf(&hex[i * 2], "%02x", sha1_hash[i]);

  // make the request
  rosauth::Authentication srv;
  srv.request.mac = string(hex);
  srv.request.client = client_ip;
  srv.request.dest = dest_ip;
  srv.request.rand = rand;
  srv.request.t = now;
  srv.request.level = user_level;
  srv.request.end = end;

  EXPECT_TRUE(client.call(srv));
  EXPECT_FALSE(srv.response.authenticated);
}

TEST(RosHashAuthentication, invalidUserLevel)
{
  string secret = "abcdefghijklmnoq";
  string client_ip = "192.168.1.101";
  string dest_ip = "192.168.1.111";
  string rand = "xyzabc";
  Time now = Time::now();
  string user_level = "admin";
  Time end = Time::now();
  end.sec += 120;

  // create the string to hash
  stringstream ss;
  ss << secret << client_ip << dest_ip << rand << now.toNSec() << "super-admin" << end.toNSec();
  string local_hash = ss.str();
  unsigned char sha1_hash[SHA_DIGEST_LENGTH];
  SHA1((unsigned char *)local_hash.c_str(), local_hash.length(), sha1_hash);

  // convert to a hex string to compare
  char hex[SHA_DIGEST_LENGTH * 2];
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    sprintf(&hex[i * 2], "%02x", sha1_hash[i]);

  // make the request
  rosauth::Authentication srv;
  srv.request.mac = string(hex);
  srv.request.client = client_ip;
  srv.request.dest = dest_ip;
  srv.request.rand = rand;
  srv.request.t = now;
  srv.request.level = user_level;
  srv.request.end = end;

  EXPECT_TRUE(client.call(srv));
  EXPECT_FALSE(srv.response.authenticated);
}

TEST(RosHashAuthentication, oldEndTime)
{
  string secret = "abcdefghijklmnoq";
  string client_ip = "192.168.1.101";
  string dest_ip = "192.168.1.111";
  string rand = "xyzabc";
  Time now = Time::now();
  string user_level = "admin";
  Time end = now;

  // create the string to hash
  stringstream ss;
  ss << secret << client_ip << dest_ip << rand << now.toNSec() << "super-admin" << end.toNSec();
  string local_hash = ss.str();
  unsigned char sha1_hash[SHA_DIGEST_LENGTH];
  SHA1((unsigned char *)local_hash.c_str(), local_hash.length(), sha1_hash);

  // convert to a hex string to compare
  char hex[SHA_DIGEST_LENGTH * 2];
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    sprintf(&hex[i * 2], "%02x", sha1_hash[i]);

  // make the request
  rosauth::Authentication srv;
  srv.request.mac = string(hex);
  srv.request.client = client_ip;
  srv.request.dest = dest_ip;
  srv.request.rand = rand;
  srv.request.t = now;
  srv.request.level = user_level;
  srv.request.end = end;

  EXPECT_TRUE(client.call(srv));
  EXPECT_FALSE(srv.response.authenticated);
}

TEST(RosHashAuthentication, invalidEndTime)
{
  string secret = "abcdefghijklmnoq";
  string client_ip = "192.168.1.101";
  string dest_ip = "192.168.1.111";
  string rand = "xyzabc";
  Time now = Time::now();
  string user_level = "admin";
  Time end = Time::now();
  end.sec += 120;
  Time end_invalid = Time::now();
  end_invalid.sec += 60;

  // create the string to hash
  stringstream ss;
  ss << secret << client_ip << dest_ip << rand << now.toNSec() << "admin" << end_invalid.toNSec();
  string local_hash = ss.str();
  unsigned char sha1_hash[SHA_DIGEST_LENGTH];
  SHA1((unsigned char *)local_hash.c_str(), local_hash.length(), sha1_hash);

  // convert to a hex string to compare
  char hex[SHA_DIGEST_LENGTH * 2];
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    sprintf(&hex[i * 2], "%02x", sha1_hash[i]);

  // make the request
  rosauth::Authentication srv;
  srv.request.mac = string(hex);
  srv.request.client = client_ip;
  srv.request.dest = dest_ip;
  srv.request.rand = rand;
  srv.request.t = now;
  srv.request.level = user_level;
  srv.request.end = end;

  EXPECT_TRUE(client.call(srv));
  EXPECT_FALSE(srv.response.authenticated);
}

// Run all the tests that were declared with TEST()
int main(int argc, char **argv)
{
  testing::InitGoogleTest(&argc, argv);

  // initialize ROS and the node
  init(argc, argv, "ros_hash_authentication_test");
  NodeHandle node;

  // setup the service client
  client = node.serviceClient<rosauth::Authentication>("authenticate");

  return RUN_ALL_TESTS();
}
