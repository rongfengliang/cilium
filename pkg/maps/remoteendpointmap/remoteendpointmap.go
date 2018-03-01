package remoteendpointmap

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	MAX_KEYS = 0xFFFF
)

// EndpointKey implements the bpf.MapKey interface.
type EndpointKey struct {
	bpf.EndpointKey
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k EndpointKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(&k) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k EndpointKey) NewValue() bpf.MapValue { return &RemoteEndpointInfo{} }

// NewEndpointKey returns an EndpointKey based on the provided IP address. The
// address family is automatically detected
func NewEndpointKey(ip net.IP) EndpointKey {
	return EndpointKey{
		EndpointKey: bpf.NewEndpointKey(ip),
	}
}

// RemoteEndpointInfo implements the bpf.MapValue interface. It contains the
// security identity of a remote endpoint.
type RemoteEndpointInfo struct {
	SecurityIdentity uint32
	Pad              [2]uint16
}

func (v RemoteEndpointInfo) String() string {
	return fmt.Sprintf("%d", v.SecurityIdentity)
}

// GetValuePtr returns the unsafe pointer to the BPF value
func (v RemoteEndpointInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(&v) }

type RemoteEndpointMap struct {
	path string
	Fd   int
}

var (
	RemoteEpMap = bpf.NewMap(
		"cilium_remote_endpoints",
		bpf.BPF_MAP_TYPE_HASH,
		int(unsafe.Sizeof(EndpointKey{})),
		int(unsafe.Sizeof(RemoteEndpointInfo{})),
		MAX_KEYS,
		0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			k, v := EndpointKey{}, RemoteEndpointInfo{}

			if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
				return nil, nil, err
			}
			return k, v, nil
		},
	)
)

func init() {
	bpf.OpenAfterMount(RemoteEpMap)
}
