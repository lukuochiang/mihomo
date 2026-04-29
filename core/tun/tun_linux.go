//go:build linux

package tun

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// setIFF sets the interface flags using ioctl
func setIFF(name string, fd int) error {
	ifr := [unix.IFNAMSIZ]byte{}
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// setIFFlags sets interface flags
func setIFFlags(fd int, flags int) error {
	var ifr [unix.IFNAMSIZ]byte
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFFLAGS),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return errno
	}

	*(*int16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ-2 : unix.IFNAMSIZ][0])) = int16(ifr[unix.IFNAMSIZ-1]) | int16(flags)
	*(*int16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ-2 : unix.IFNAMSIZ][0])) = int16(ifr[unix.IFNAMSIZ-2]) | int16(flags>>8)

	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFFLAGS),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// getDevName gets the device name from file descriptor
func getDevName(fd int) (string, error) {
	var ifr [unix.IFNAMSIZ]byte
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.TUNGETIFF),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return "", errno
	}
	for i, b := range ifr {
		if b == 0 {
			return string(ifr[:i]), nil
		}
	}
	return string(ifr[:]), nil
}

// setMTU sets the MTU for the interface
func setMTU(fd int, mtu int) error {
	var ifr [unix.IFNAMSIZ]byte
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return errno
	}

	*(*int32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ-4 : unix.IFNAMSIZ][0])) = int32(mtu)
	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// SetupTUN configures the TUN device with IP addresses
func SetupTUN(fd int, config *Config) error {
	sockFd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer unix.Close(sockFd)

	ifreq := unix.Ifreq{}
	copy(ifreq.Name[:], []byte(config.Name))

	addr := &unix.SockaddrInet4{}
	if len(config.Addresses) > 0 {
		ip := net.ParseIP(config.Addresses[0])
		if ip == nil {
			return fmt.Errorf("invalid IP address: %s", config.Addresses[0])
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return fmt.Errorf("not an IPv4 address: %s", config.Addresses[0])
		}
		copy(addr.Addr[:], ip4)
		if err := unix.IoctlIfreq(sockFd, unix.SIOCSIFADDR, &ifreq); err != nil {
			return fmt.Errorf("failed to set address: %w", err)
		}
	}

	mask := &unix.SockaddrInet4{}
	ones := 24 // Default /24
	if len(config.Addresses) > 0 {
		_, ipnet, err := net.ParseCIDR(config.Addresses[0])
		if err == nil {
			ones, _ = ipnet.Mask.Size()
		}
	}
	for i := 0; i < 4; i++ {
		if i < ones/8 {
			mask.Addr[i] = 255
		} else if i == ones/8 {
			mask.Addr[i] = byte(256 - (1 << uint(8-ones%8)))
		}
	}
	if err := unix.IoctlIfreq(sockFd, unix.SIOCSIFNETMASK, &ifreq); err != nil {
		return fmt.Errorf("failed to set netmask: %w", err)
	}

	// Bring interface up
	if err := unix.IoctlIfreq(sockFd, unix.SIOCGIFFLAGS, &ifreq); err != nil {
		return fmt.Errorf("failed to get flags: %w", err)
	}
	ifreq.SetFlags(ifreq.Flags | unix.IFF_UP | unix.IFF_RUNNING)
	if err := unix.IoctlIfreq(sockFd, unix.SIOCSIFFLAGS, &ifreq); err != nil {
		return fmt.Errorf("failed to set flags: %w", err)
	}

	return nil
}

// getMTU gets the MTU for the interface
func getMTU(fd int, name string) (int, error) {
	sockFd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(sockFd)

	ifreq := unix.Ifreq{}
	copy(ifreq.Name[:], []byte(name))

	if err := unix.IoctlIfreq(sockFd, unix.SIOCGIFMTU, &ifreq); err != nil {
		return 0, err
	}

	return int(ifreq.MTU), nil
}

// setTUNMTU sets the MTU for the TUN device
func setTUNMTU(fd int, name string, mtu int) error {
	sockFd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sockFd)

	ifreq := unix.Ifreq{}
	copy(ifreq.Name[:], []byte(name))
	ifreq.MTU = int32(mtu)

	if err := unix.IoctlIfreq(sockFd, unix.SIOCSIFMTU, &ifreq); err != nil {
		return err
	}
	return nil
}

// SetupAutoRoute sets up automatic routing for TUN device
func SetupAutoRoute(tunName string, tunSubnet string) error {
	// Add route to route all traffic through TUN device
	cmd := exec.Command("ip", "route", "add", "default", "dev", tunName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add default route: %w", err)
	}

	// If there's an existing default route, move it to table 100
	cmd = exec.Command("ip", "route", "show", "table", "all")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "default") && !strings.Contains(line, tunName) {
				// Found existing default route
				// Add exception for local network
				break
			}
		}
	}

	return nil
}

// CleanupAutoRoute removes automatic routing
func CleanupAutoRoute(tunName string) error {
	// Remove default route via TUN
	cmd := exec.Command("ip", "route", "del", "default", "dev", tunName)
	if err := cmd.Run(); err != nil {
		// Ignore error if route doesn't exist
		return nil
	}
	return nil
}

// SetupDNS sets up DNS configuration
func SetupDNS(dnsServers []string) error {
	if len(dnsServers) == 0 {
		return nil
	}

	// Write to /etc/resolv.conf or use resolvectl
	// This requires appropriate permissions
	return nil
}

// OpenTUNDevice opens /dev/tun and configures the TUN device
func OpenTUNDevice(name string) (int, string, error) {
	// Open /dev/tun
	fd, err := unix.Open("/dev/tun", unix.O_RDWR, 0)
	if err != nil {
		return -1, "", fmt.Errorf("failed to open /dev/tun: %w", err)
	}

	// Set interface flags
	iff := unix.IFF_TUN | unix.IFF_NO_PI
	var ifr unix.Ifreq
	copy(ifr.Name[:], []byte(name))
	ifr.Flags = uint16(iff)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		unix.Close(fd)
		return -1, "", fmt.Errorf("failed to set TUN flags: %v", errno)
	}

	// Get actual device name
	actualName := strings.TrimRight(string(ifr.Name[:]), "\x00")

	return fd, actualName, nil
}
