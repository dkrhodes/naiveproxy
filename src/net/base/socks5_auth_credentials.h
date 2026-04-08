// Copyright 2025 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_SOCKS5_AUTH_CREDENTIALS_H_
#define NET_BASE_SOCKS5_AUTH_CREDENTIALS_H_

#include <string>

#include "net/base/net_export.h"

namespace net {

// Username/password for SOCKS5 RFC 1929 username/password authentication.
struct NET_EXPORT_PRIVATE Socks5AuthCredentials {
  std::string username;
  std::string password;

  bool operator==(const Socks5AuthCredentials&) const = default;
  auto operator<=>(const Socks5AuthCredentials&) const = default;
};

}  // namespace net

#endif  // NET_BASE_SOCKS5_AUTH_CREDENTIALS_H_
