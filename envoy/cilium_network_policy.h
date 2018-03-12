#pragma once

#include "envoy/local_info/local_info.h"
#include "envoy/upstream/cluster_manager.h"
#include "envoy/event/dispatcher.h"

#include "common/common/logger.h"
#include "common/router/config_utility.h"
#include "envoy/config/subscription.h"
#include "envoy/singleton/instance.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/http/header_map.h"

#include "cilium/npds.pb.h"

namespace Envoy {
namespace Cilium {

class NetworkPolicyMap : public Singleton::Instance,
                         Config::SubscriptionCallbacks<cilium::NetworkPolicy>,
                         public Logger::Loggable<Logger::Id::config> {
public:
  NetworkPolicyMap(const envoy::api::v2::core::ApiConfigSource& api_config_source,
		   const LocalInfo::LocalInfo& local_info,
		   Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
		   Stats::Scope &scope, ThreadLocal::SlotAllocator& tls);
  NetworkPolicyMap(std::unique_ptr<Envoy::Config::Subscription<cilium::NetworkPolicy>>&& subscription,
		   ThreadLocal::SlotAllocator& tls);
  ~NetworkPolicyMap() {}

  class PolicyInstance {
  public:
    PolicyInstance(uint64_t hash, const cilium::NetworkPolicy& proto)
        : hash_(hash), policy_proto_(proto), ingress_(policy_proto_.ingress_per_port_policies()),
          egress_(policy_proto_.egress_per_port_policies()) {}

    uint64_t hash_;
    const cilium::NetworkPolicy policy_proto_;

  protected:
    class HttpNetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
    public:
      HttpNetworkPolicyRule(const cilium::HttpNetworkPolicyRule& rule) {
	ENVOY_LOG(trace, "Cilium L7 HttpNetworkPolicyRule():");
	for (const auto& header: rule.headers()) {
	  headers_.emplace_back(header);
	  const auto& header_data = headers_.back();
	  ENVOY_LOG(trace, "Cilium L7 HttpNetworkPolicyRule(): HeaderData {}={} ({})",
		    header_data.name_.get(), header_data.value_, header_data.is_regex_ ? "regex" : "literal");
	}
      }

      bool Matches(const Envoy::Http::HeaderMap& headers) const {
	// Empty set matches any headers.
	return Envoy::Router::ConfigUtility::matchHeaders(headers, headers_);
      }

      std::vector<Envoy::Router::ConfigUtility::HeaderData> headers_; // Allowed if empty.
    };
    
    class PortNetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
    public:
      PortNetworkPolicyRule(const cilium::PortNetworkPolicyRule& rules) {
	for (const auto& remote: rules.remote_policies()) {
	  ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): Allowing remote {}", remote);
	  allowed_remotes_.emplace(remote);
	}
	for (const auto& http_rule: rules.http_rules().http_rules()) {
	  http_rules_.emplace_back(http_rule);
	}
      }

      bool Matches(uint64_t remote_id, const Envoy::Http::HeaderMap& headers) const {
	// Remote ID must match if we have any.
	if (allowed_remotes_.size()) {
	  bool matches = false;
	  for (const auto& remote: allowed_remotes_) {
	    if (remote == remote_id) {
	      matches = true;
	      break;
	    }
	  }
	  if (!matches) {
	    return false;
	  }
	}
	// Empty set matches any payload
	if (http_rules_.size() == 0) {
	  return true;
	}	
	for (const auto& rule: http_rules_) {
	  if (rule.Matches(headers)) {
	    return true;
	  }
	}
	return false;
      }

      std::unordered_set<uint64_t> allowed_remotes_; // Everyone allowed if empty.
      std::vector<HttpNetworkPolicyRule> http_rules_; // Allowed if empty, but remote is checked first.
    };

    class PortNetworkPolicyRules : public Logger::Loggable<Logger::Id::config> {
    public:
      PortNetworkPolicyRules(const google::protobuf::RepeatedPtrField<cilium::PortNetworkPolicyRule>& rules) {
	if (rules.size() == 0) {
	    ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules(): No rules, will allow everything.");
	}
	for (const auto& it: rules) {
	  rules_.emplace_back(PortNetworkPolicyRule(it));
	}
      }

      bool Matches(uint64_t remote_id, const Envoy::Http::HeaderMap& headers) const {
	// Empty set matches any payload from anyone
	if (rules_.size() == 0) {
	  return true;
	}
	for (const auto& rule: rules_) {
	  if (rule.Matches(remote_id, headers)) {
	    return true;
	  }
	}
	return false;
      }

      std::vector<PortNetworkPolicyRule> rules_; // Allowed if empty.
    };
    
    class PortNetworkPolicy : public Logger::Loggable<Logger::Id::config> {
    public:
      PortNetworkPolicy(const google::protobuf::RepeatedPtrField<cilium::PortNetworkPolicy>& rules) {
	for (const auto& it: rules) {
	  // TODO: Handle Missing Protocol
	  if (it.protocol() == envoy::api::v2::core::SocketAddress::TCP) {
	    // port may be zero, which matches any port.
	    ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicy(): installing TCP policy for port {}", it.port());
	    rules_.emplace(it.port(), PortNetworkPolicyRules(it.rules()));
	  } else {
	    ENVOY_LOG(warn, "Cilium L7 PortNetworkPolicy(): NOT installing non-TCP policy");
	  }
	}
      }

      bool Matches(uint32_t port, uint64_t remote_id, const Envoy::Http::HeaderMap& headers) const {
	auto range = rules_.equal_range(port);
	for (auto& it = range.first; it != range.second; ++it) {
	  if (it->second.Matches(remote_id, headers)) {
	    return true;
	  }
	}
	// Check for any rules that wildcard the port
	if (port != 0) {
	  return Matches(0, remote_id, headers);
	}
	return false;
      }

      std::unordered_map<uint32_t, PortNetworkPolicyRules> rules_;
    };

  public:
    bool Allowed(bool ingress, uint32_t port, uint64_t remote_id,
		 const Envoy::Http::HeaderMap& headers) const {
      return ingress
	? ingress_.Matches(port, remote_id, headers)
	: egress_.Matches(port, remote_id, headers);
    }

  private:
    const PortNetworkPolicy ingress_;
    const PortNetworkPolicy egress_;
  };

  struct ThreadLocalPolicyMap : public ThreadLocal::ThreadLocalObject {
    std::map<uint32_t, std::shared_ptr<const PolicyInstance>> policies_;
  };

  const std::shared_ptr<const PolicyInstance>& GetPolicyInstance(uint32_t id) const {
    const ThreadLocalPolicyMap& map = tls_->getTyped<ThreadLocalPolicyMap>();
    auto it = map.policies_.find(id);
    if (it == map.policies_.end()) {
      return null_instance_;
    }
    return it->second;
  }

  bool Allowed(uint32_t id, bool ingress, uint32_t port, uint64_t remote_id,
	       const Envoy::Http::HeaderMap& headers) const {
    ENVOY_LOG(trace, "Cilium L7 NetworkPolicyMap::Allowed(): {} lookup for id {}, port {}, remote_id: {}", ingress ? "Ingress" : "Egress", id, port, remote_id);
    if (tls_->get().get() == nullptr) {
      ENVOY_LOG(warn, "Cilium L7 NetworkPolicyMap::Allowed(): NULL TLS object!");
      return false;
    }
    const auto& npmap = tls_->getTyped<ThreadLocalPolicyMap>().policies_;
    auto it = npmap.find(id);
    if (it == npmap.end()) {
      ENVOY_LOG(trace, "Cilium L7 NetworkPolicyMap::Allowed(): No policy found for {}", id);
      return false;
    }
    return it->second->Allowed(ingress, port, remote_id, headers);
  }

  // Config::SubscriptionCallbacks
  void onConfigUpdate(const ResourceVector& resources) override;
  void onConfigUpdateFailed(const EnvoyException* e) override;
  std::string resourceName(const ProtobufWkt::Any& resource) override {
    std::string name = fmt::format("{}",
				   MessageUtil::anyConvert<cilium::NetworkPolicy>(resource).policy());
    return name;
  }

private:
  ThreadLocal::SlotPtr tls_;
  std::unique_ptr<Envoy::Config::Subscription<cilium::NetworkPolicy>> subscription_;
  const std::shared_ptr<const PolicyInstance> null_instance_{nullptr};
};

} // namespace Cilium
} // namespace Envoy
