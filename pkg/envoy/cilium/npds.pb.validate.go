// Code generated by protoc-gen-validate
// source: cilium/npds.proto
// DO NOT EDIT!!!

package cilium

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang/protobuf/ptypes"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = ptypes.DynamicAny{}
)

// Validate checks the field values on NetworkPolicy with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *NetworkPolicy) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for Policy

	for idx, item := range m.GetIngressPerPortPolicies() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface {
			Validate() error
		}); ok {
			if err := v.Validate(); err != nil {
				return NetworkPolicyValidationError{
					Field:  fmt.Sprintf("IngressPerPortPolicies[%v]", idx),
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	for idx, item := range m.GetEgressPerPortPolicies() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface {
			Validate() error
		}); ok {
			if err := v.Validate(); err != nil {
				return NetworkPolicyValidationError{
					Field:  fmt.Sprintf("EgressPerPortPolicies[%v]", idx),
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	return nil
}

// NetworkPolicyValidationError is the validation error returned by
// NetworkPolicy.Validate if the designated constraints aren't met.
type NetworkPolicyValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e NetworkPolicyValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sNetworkPolicy.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = NetworkPolicyValidationError{}

// Validate checks the field values on PortNetworkPolicy with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned.
func (m *PortNetworkPolicy) Validate() error {
	if m == nil {
		return nil
	}

	if m.GetPort() > 65535 {
		return PortNetworkPolicyValidationError{
			Field:  "Port",
			Reason: "value must be less than or equal to 65535",
		}
	}

	// no validation rules for Protocol

	for idx, item := range m.GetRules() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface {
			Validate() error
		}); ok {
			if err := v.Validate(); err != nil {
				return PortNetworkPolicyValidationError{
					Field:  fmt.Sprintf("Rules[%v]", idx),
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	return nil
}

// PortNetworkPolicyValidationError is the validation error returned by
// PortNetworkPolicy.Validate if the designated constraints aren't met.
type PortNetworkPolicyValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e PortNetworkPolicyValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sPortNetworkPolicy.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = PortNetworkPolicyValidationError{}

// Validate checks the field values on PortNetworkPolicyRule with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *PortNetworkPolicyRule) Validate() error {
	if m == nil {
		return nil
	}

	_PortNetworkPolicyRule_RemotePolicies_Unique := make(map[uint64]struct{}, len(m.GetRemotePolicies()))

	for idx, item := range m.GetRemotePolicies() {
		_, _ = idx, item

		if _, exists := _PortNetworkPolicyRule_RemotePolicies_Unique[item]; exists {
			return PortNetworkPolicyRuleValidationError{
				Field:  fmt.Sprintf("RemotePolicies[%v]", idx),
				Reason: "repeated value must contain unique items",
			}
		} else {
			_PortNetworkPolicyRule_RemotePolicies_Unique[item] = struct{}{}
		}

		// no validation rules for RemotePolicies[idx]
	}

	switch m.L7Rules.(type) {

	case *PortNetworkPolicyRule_HttpRules:

		if v, ok := interface{}(m.GetHttpRules()).(interface {
			Validate() error
		}); ok {
			if err := v.Validate(); err != nil {
				return PortNetworkPolicyRuleValidationError{
					Field:  "HttpRules",
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	return nil
}

// PortNetworkPolicyRuleValidationError is the validation error returned by
// PortNetworkPolicyRule.Validate if the designated constraints aren't met.
type PortNetworkPolicyRuleValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e PortNetworkPolicyRuleValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sPortNetworkPolicyRule.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = PortNetworkPolicyRuleValidationError{}

// Validate checks the field values on HttpNetworkPolicyRules with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *HttpNetworkPolicyRules) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetHttpRules()) < 1 {
		return HttpNetworkPolicyRulesValidationError{
			Field:  "HttpRules",
			Reason: "value must contain at least 1 item(s)",
		}
	}

	for idx, item := range m.GetHttpRules() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface {
			Validate() error
		}); ok {
			if err := v.Validate(); err != nil {
				return HttpNetworkPolicyRulesValidationError{
					Field:  fmt.Sprintf("HttpRules[%v]", idx),
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	return nil
}

// HttpNetworkPolicyRulesValidationError is the validation error returned by
// HttpNetworkPolicyRules.Validate if the designated constraints aren't met.
type HttpNetworkPolicyRulesValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e HttpNetworkPolicyRulesValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHttpNetworkPolicyRules.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = HttpNetworkPolicyRulesValidationError{}

// Validate checks the field values on HttpNetworkPolicyRule with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *HttpNetworkPolicyRule) Validate() error {
	if m == nil {
		return nil
	}

	for idx, item := range m.GetHeaders() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface {
			Validate() error
		}); ok {
			if err := v.Validate(); err != nil {
				return HttpNetworkPolicyRuleValidationError{
					Field:  fmt.Sprintf("Headers[%v]", idx),
					Reason: "embedded message failed validation",
					Cause:  err,
				}
			}
		}

	}

	return nil
}

// HttpNetworkPolicyRuleValidationError is the validation error returned by
// HttpNetworkPolicyRule.Validate if the designated constraints aren't met.
type HttpNetworkPolicyRuleValidationError struct {
	Field  string
	Reason string
	Cause  error
	Key    bool
}

// Error satisfies the builtin error interface
func (e HttpNetworkPolicyRuleValidationError) Error() string {
	cause := ""
	if e.Cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.Cause)
	}

	key := ""
	if e.Key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHttpNetworkPolicyRule.%s: %s%s",
		key,
		e.Field,
		e.Reason,
		cause)
}

var _ error = HttpNetworkPolicyRuleValidationError{}
