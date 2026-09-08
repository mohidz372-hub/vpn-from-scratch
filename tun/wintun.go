package tun

import (
	"fmt"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type WinTunDevice struct {
	realDevice tun.Device
	name       string
}

// CreateWinTun creates a new TUN device on Windows
// This requires ADMIN privileges
func CreateWinTun(interfaceName string) (*WinTunDevice, error) {
	fmt.Printf("[WinTun] Creating TUN device: %s\n", interfaceName)
	fmt.Println("[WinTun] ⚠️  This requires ADMIN privileges!")

	// Create TUN device
	realDevice, err := tun.CreateTUN(interfaceName, device.DefaultMTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	fmt.Println("[WinTun] ✓ TUN device created")

	// Bring up the interface
	realInterfaceName, err := realDevice.Name()
	if err != nil {
		realDevice.Close()
		return nil, fmt.Errorf("failed to get interface name: %w", err)
	}
	fmt.Printf("[WinTun] Interface name: %s\n", realInterfaceName)
	// Get actual MTU
	realMTU := device.DefaultMTU
	fmt.Printf("[WinTun] MTU: %d\n", realMTU)

	return &WinTunDevice{
		realDevice: realDevice,
		name:       realInterfaceName,
	}, nil
}

// ConfigureIP sets the IP address on the TUN device
// Note: On Windows, IP configuration requires netsh command
func (wtd *WinTunDevice) ConfigureIP(ipAddr string, netmask string) error {
	fmt.Printf("[WinTun] Configuring IP: %s/%s\n", ipAddr, netmask)
	fmt.Println("[WinTun] ℹ️  IP configuration must be done manually or via netsh")
	fmt.Printf("[WinTun] Run in admin PowerShell:\n")
	fmt.Printf("  netsh int ip set address \"%s\" static %s %s\n", wtd.name, ipAddr, netmask)
	return nil
}

// ReadPackets reads packets from the TUN device
func (wtd *WinTunDevice) ReadPackets() ([][]byte, []int, error) {
	// Allocate packet buffers
	packets := make([][]byte, device.DefaultMTU)
	sizes := make([]int, len(packets))

	for i := range packets {
		packets[i] = make([]byte, device.DefaultMTU)
	}

	// Read from TUN
	n, err := wtd.realDevice.Read(packets, sizes, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("TUN read error: %w", err)
	}

	return packets[:n], sizes[:n], nil
}

// WritePackets writes packets to the TUN device
func (wtd *WinTunDevice) WritePackets(packets [][]byte) error {
	// Create sizes slice
	sizes := make([]int, len(packets))
	for i, pkt := range packets {
		sizes[i] = len(pkt)
	}

	// Write to TUN
	_, err := wtd.realDevice.Write(packets, 0)
	if err != nil {
		return fmt.Errorf("TUN write error: %w", err)
	}

	return nil
}

// Close closes the TUN device
func (wtd *WinTunDevice) Close() error {
	fmt.Println("[WinTun] Closing TUN device...")
	if wtd.realDevice != nil {
		return wtd.realDevice.Close()
	}
	return nil
}

// GetName returns the interface name
func (wtd *WinTunDevice) GetName() string {
	return wtd.name
}
