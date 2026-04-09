// Copyright 2025 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/cronet/cronet_proxy_delegate.h"

#include "base/base64.h"
#include "base/logging.h"
#include "base/notreached.h"
#include "base/strings/strcat.h"
#include "base/trace_event/trace_event.h"
#include "base/types/expected.h"
#include "build/build_config.h"
#include "net/base/completion_once_callback.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_delegate.h"
#include "net/base/socks5_auth_credentials.h"
#include "net/http/http_request_headers.h"
#include "net/proxy_resolution/proxy_info.h"
#include "url/gurl.h"

namespace cronet {

namespace {

void MaybeAddBasicProxyAuthorization(net::HttpRequestHeaders& headers,
                                       const cronet::proto::Proxy& proxy) {
  if (!proxy.has_username() || proxy.username().empty()) {
    return;
  }
  std::string token =
      base::StrCat({"Basic ", base::Base64Encode(base::StrCat(
                                  {proxy.username(), ":", proxy.password()}))});
  headers.SetHeader("Proxy-Authorization", token);
}

}  // namespace

CronetProxyDelegate::CronetProxyDelegate(
    cronet::proto::ProxyOptions proxy_options,
    CronetContext::NetworkTasks* network_tasks)
    : proxy_options_(std::move(proxy_options)), network_tasks_(network_tasks) {}

CronetProxyDelegate::~CronetProxyDelegate() = default;

void CronetProxyDelegate::OnResolveProxy(
    const GURL& url,
    const net::NetworkAnonymizationKey& network_anonymization_key,
    const std::string& method,
    const net::ProxyRetryInfoMap& proxy_retry_info,
    net::ProxyInfo* result) {
  TRACE_EVENT_BEGIN("cronet", "CronetProxyDelegate::OnResolveProxy", "url", url,
                    "method", method, "initial_proxy_info",
                    result->ToDebugString());
  // Using a self-calling lambda to make sure we always call TRACE_EVENT_END
  // regardless of early returns.
  [&] {
    net::ProxyList proxy_list;
    for (int i = 0; i < proxy_options_.proxies_size(); ++i) {
      const auto& proxy_server = proxy_options_.proxies(i);
      if (proxy_server.scheme() == cronet::proto::ProxyScheme::DIRECT) {
        auto chain =
            net::ProxyChain::WithOpaqueData(std::vector<net::ProxyServer>(),
                                            /*opaque_data=*/i);
        CHECK(chain.IsValid());
        proxy_list.AddProxyChain(std::move(chain));
      } else {
        net::ProxyServer::Scheme scheme =
            net::ProxyServer::Scheme::SCHEME_INVALID;
        switch (proxy_server.scheme()) {
          case cronet::proto::ProxyScheme::HTTP:
            scheme = net::ProxyServer::Scheme::SCHEME_HTTP;
            break;
          case cronet::proto::ProxyScheme::HTTPS:
            scheme = net::ProxyServer::Scheme::SCHEME_HTTPS;
            break;
          case cronet::proto::ProxyScheme::SOCKS4:
            scheme = net::ProxyServer::Scheme::SCHEME_SOCKS4;
            break;
          case cronet::proto::ProxyScheme::SOCKS5:
            scheme = net::ProxyServer::Scheme::SCHEME_SOCKS5;
            break;
          case cronet::proto::ProxyScheme::QUIC:
            scheme = net::ProxyServer::Scheme::SCHEME_QUIC;
            break;
          default:
            NOTREACHED();
        }
        std::optional<net::Socks5AuthCredentials> socks5_auth;
        if (scheme == net::ProxyServer::Scheme::SCHEME_SOCKS5 &&
            proxy_server.has_username() && !proxy_server.username().empty()) {
          socks5_auth = net::Socks5AuthCredentials{
              std::string(proxy_server.username()),
              std::string(proxy_server.password())};
        }
        auto chain = net::ProxyChain::WithOpaqueData(
            std::vector<net::ProxyServer>{net::ProxyServer(
                scheme,
                net::HostPortPair(proxy_server.host(), proxy_server.port()))},
            /*opaque_data=*/i, std::move(socks5_auth));
        CHECK(chain.IsValid());
        proxy_list.AddProxyChain(std::move(chain));
      }
    }
    result->UseProxyList(proxy_list);
  }();
  TRACE_EVENT_END("cronet", "resulting_proxy_info", result->ToDebugString());
}

std::optional<bool> CronetProxyDelegate::CanFalloverToNextProxyOverride(
    const net::ProxyChain& proxy_chain,
    int net_error) {
  // We promise this in org.chromium.net.ProxyOptions's documentation.
  return true;
}

void CronetProxyDelegate::OnSuccessfulRequestAfterFailures(
    const net::ProxyRetryInfoMap& proxy_retry_info) {
  TRACE_EVENT_INSTANT("cronet",
                      "CronetProxyDelegate::OnSuccessfulRequestAfterFailures");
}

void CronetProxyDelegate::OnFallback(const net::ProxyChain& bad_chain,
                                     int net_error) {
  TRACE_EVENT_INSTANT("cronet", "CronetProxyDelegate::OnFallback", "bad_chain",
                      bad_chain.ToDebugString(), "net_error", net_error);
}

base::expected<net::HttpRequestHeaders, net::Error>
CronetProxyDelegate::OnBeforeTunnelRequest(
    const net::ProxyChain& proxy_chain,
    size_t proxy_index,
    OnBeforeTunnelRequestCallback callback) {
  TRACE_EVENT_BEGIN("cronet", "CronetProxyDelegate::OnBeforeTunnelRequest",
                    "proxy_chain", proxy_chain.ToDebugString(), "proxy_index",
                    proxy_index);
  CHECK(proxy_chain.opaque_data().has_value());
  const int chain_id = static_cast<int>(*proxy_chain.opaque_data());
  CHECK(chain_id >= 0 && chain_id < proxy_options_.proxies_size());
  const cronet::proto::Proxy& proxy = proxy_options_.proxies(chain_id);

  const net::ProxyServer& proxy_server =
      proxy_chain.GetProxyServer(proxy_index);
  if (proxy_server.is_socks()) {
    TRACE_EVENT_END("cronet", "result", "empty_headers_socks");
    return net::HttpRequestHeaders();
  }

#if BUILDFLAG(IS_ANDROID)
  const bool has_embedded_auth =
      proxy.has_username() && !proxy.username().empty();
  if ((proxy.scheme() == cronet::proto::ProxyScheme::HTTP ||
       proxy.scheme() == cronet::proto::ProxyScheme::HTTPS) &&
      !has_embedded_auth) {
    CHECK(network_tasks_);
    network_tasks_->OnBeforeTunnelRequest(chain_id, std::move(callback));
    const auto result = net::ERR_IO_PENDING;
    TRACE_EVENT_END("cronet", "result", result);
    return base::unexpected(result);
  }
#endif  // BUILDFLAG(IS_ANDROID)

  net::HttpRequestHeaders headers;
  MaybeAddBasicProxyAuthorization(headers, proxy);
  TRACE_EVENT_END("cronet", "result", "sync_headers");
  return headers;
}

net::Error CronetProxyDelegate::OnTunnelHeadersReceived(
    const net::ProxyChain& proxy_chain,
    size_t proxy_index,
    const net::HttpResponseHeaders& response_headers,
    net::CompletionOnceCallback callback) {
  TRACE_EVENT_BEGIN("cronet", "CronetProxyDelegate::OnTunnelHeadersReceived",
                    "proxy_chain", proxy_chain.ToDebugString(), "proxy_index",
                    proxy_index);
#if BUILDFLAG(IS_ANDROID)
  CHECK(proxy_chain.opaque_data().has_value());
  CHECK(network_tasks_);
  network_tasks_->OnTunnelHeadersReceived(
      static_cast<int>(*proxy_chain.opaque_data()), response_headers,
      std::move(callback));
  const auto result = net::ERR_IO_PENDING;
  TRACE_EVENT_END("cronet", "result", result);
  return result;
#else
  TRACE_EVENT_END("cronet", "result", net::OK);
  return net::OK;
#endif  // BUILDFLAG(IS_ANDROID)
}

void CronetProxyDelegate::SetProxyResolutionService(
    net::ProxyResolutionService* proxy_resolution_service) {
  TRACE_EVENT_INSTANT("cronet",
                      "CronetProxyDelegate::SetProxyResolutionService");
}

}  // namespace cronet
