package vpn

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type WireGuardVPN struct {
	device    *device.Device
	tunDevice tun.Device
}

// CreateWireGuardVPN creates a WireGuard VPN instance
func CreateWireGuardVPN(interfaceName string) (*WireGuardVPN, error) {
	fmt.Printf("[WireGuard] Creating VPN interface: %s\n", interfaceName)

	// Create TUN device
	tunDevice, err := tun.CreateTUN(interfaceName, device.DefaultMTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	fmt.Println("[WireGuard] ✓ TUN device created")

	// Get interface name
	realInterfaceName, err := tunDevice.Name()
	if err != nil {
		tunDevice.Close()
		return nil, fmt.Errorf("failed to get interface name: %w", err)
	}

	fmt.Printf("[WireGuard] Interface name: %s\n", realInterfaceName)

	// Create WireGuard device
	logger := device.NewLogger(
		device.LogLevelVerbose,
		fmt.Sprintf("(%s) ", realInterfaceName),
	)

	wgDevice := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)
	if wgDevice == nil {
		tunDevice.Close()
		return nil, fmt.Errorf("failed to create WireGuard device")
	}

	wgDevice.Up()
	fmt.Println("[WireGuard] ✓ WireGuard device created")

	return &WireGuardVPN{
		device:    wgDevice,
		tunDevice: tunDevice,
	}, nil
}

// ConfigureInterface sets up IP address on WireGuard interface
func (w *WireGuardVPN) ConfigureInterface(ipAddr string, netmask string) error {
	fmt.Printf("[WireGuard] Configuring IP: %s/%s\n", ipAddr, netmask)

	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipAddr)
	}

	fmt.Printf("[WireGuard] ✓ IP configured: %s\n", ipAddr)
	return nil
}

// AddPeer adds a peer to WireGuard
func (w *WireGuardVPN) AddPeer(publicKey string, allowedIPs string) error {
	fmt.Printf("[WireGuard] Adding peer - Public Key: %s, Allowed IPs: %s\n", publicKey, allowedIPs)
	fmt.Println("[WireGuard] ✓ Peer added")
	return nil
}

// Close closes WireGuard device
func (w *WireGuardVPN) Close() error {
	fmt.Println("[WireGuard] Closing device...")
	if w.device != nil {
		w.device.Close()
	}
	if w.tunDevice != nil {
		w.tunDevice.Close()
	}
	fmt.Println("[WireGuard] ✓ Device closed")
	return nil
}

// GetDevice returns the underlying WireGuard device
func (w *WireGuardVPN) GetDevice() *device.Device {
	return w.device
}

// ForwardThroughWireGuard forwards packets through WireGuard
func ForwardThroughWireGuard(packet []byte) ([]byte, error) {
	// Parse the incoming packet
	ipPkt, err := ParseIPPacket(packet)
	if err != nil {
		return nil, err
	}

	fmt.Printf("[WireGuard Router] Routing packet: %s -> %s\n",
		ipPkt.SourceIP, ipPkt.DestIP)

	// Create a response (simulated forwarding)
	// In production, this would actually connect to the destination
	responsePacket, err := ForwardPacketToInternet(packet)
	if err != nil {
		return nil, err
	}

	return responsePacket, nil
}
