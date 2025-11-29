package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()
var rdb = redis.NewClient(&redis.Options{
	Addr: "127.0.0.1:6379", // Redis
})

func allowIP(ip string) {
	commands := []string{
		fmt.Sprintf("iptables -t nat -C CAPTIVE_PORTAL -s %s -j RETURN 2>/dev/null || iptables -t nat -I CAPTIVE_PORTAL 1 -s %s -j RETURN", ip, ip),
		fmt.Sprintf("iptables -I FORWARD -i wlan1 -s %s -j ACCEPT", ip),
	}

	for _, cmd := range commands {
		exec.Command("bash", "-c", cmd).Run()
	}
}

func getMAC(ip string) (string, error) {
	// Read from arp table
	cmd := exec.Command("bash", "-c", fmt.Sprintf("ip neigh | grep '%s' | awk '{print $5}'", ip))
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	mac := strings.TrimSpace(string(out))
	if mac == "" {
		return "", fmt.Errorf("MAC not found for IP %s", ip)
	}

	return mac, nil
}

func cleanupDevice(ip string) {
	mac := rdb.Get(ctx, "IP:"+ip).Val()

	// Remove iptables rules
	cmds := []string{
		fmt.Sprintf("iptables -t nat -D CAPTIVE_PORTAL -s %s -j RETURN 2>/dev/null", ip),
		fmt.Sprintf("iptables -D FORWARD -i wlan1 -s %s -j ACCEPT 2>/dev/null", ip),
	}
	for _, cmd := range cmds {
		exec.Command("bash", "-c", cmd).Run()
	}

	// Remove IP and MAC from Redis
	rdb.Del(ctx, "IP:"+ip)
	rdb.Del(ctx, "MAC:"+mac)

	log.Printf("✅ Fully removed disconnected device IP=%s MAC=%s", ip, mac)
}

func getHostname(ip string) string {
	// Try mDNS (Linux systems)
	cmd := exec.Command("bash", "-c", fmt.Sprintf("avahi-resolve -a %s 2>/dev/null | awk '{print $2}'", ip))
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		return strings.TrimSpace(string(out))
	}

	// Try NetBIOS (Windows devices)
	cmd = exec.Command("bash", "-c", fmt.Sprintf("nmblookup -A %s 2>/dev/null | grep '<00>' | awk '{print $1}'", ip))
	out, err = cmd.Output()
	if err == nil && len(out) > 0 {
		return strings.TrimSpace(string(out))
	}

	// Try reverse DNS
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}

	return "unknown"
}

func main() {
	router := gin.Default()
	router.LoadHTMLGlob("templates/*.html")

	// Main portal page
	router.GET("/", func(c *gin.Context) {
		c.HTML(200, "portal.html", nil)
	})

	// Android captive portal check
	router.GET("/generate_204", func(c *gin.Context) {
		c.Redirect(302, "/") // redirect captive check to portal
	})

	// Authorization form submission
	router.POST("/authorize", func(c *gin.Context) {
		ip := c.ClientIP()
		if ip == "" {
			c.HTML(http.StatusOK, "portal.html", gin.H{"error": "Unable to detect your IP."})
			return
		}

		mac, err := getMAC(ip)
		if err != nil {
			c.HTML(http.StatusOK, "portal.html", gin.H{"error": "Unable to detect your MAC. Try reconnecting."})
			return
		}
		mac = strings.ToLower(mac)

		// Check Redis for existing authorization
		allowed, _ := rdb.Get(ctx, "MAC:"+mac).Result()
		if allowed == "allowed" {
			allowIP(ip)
			c.HTML(http.StatusOK, "portal.html", gin.H{"message": "You are already authorized."})
			return
		}

		// Save MAC & IP
		rdb.Set(ctx, "MAC:"+mac, "allowed", 24*time.Hour)
		rdb.Set(ctx, "IP:"+ip, mac, 24*time.Hour)

		// Whitelist IP
		allowIP(ip)

		// Apply iptables rules
		cmds := []string{
			fmt.Sprintf("iptables -t nat -C CAPTIVE_PORTAL -s %s -j RETURN 2>/dev/null || iptables -t nat -I CAPTIVE_PORTAL 1 -s %s -j RETURN", ip, ip),
			fmt.Sprintf("iptables -I FORWARD -i wlan1 -s %s -j ACCEPT", ip),
			fmt.Sprintf("iptables -t nat -D PREROUTING -i wlan1 -p udp --dport 53 -s %s -j DNAT --to-destination 192.168.10.1 2>/dev/null", ip),
			"iptables -D FORWARD -i wlan1 -p tcp --dport 443 -j REJECT 2>/dev/null || true",
		}

		for _, cmd := range cmds {
			if err := exec.Command("bash", "-c", cmd).Run(); err != nil {
				log.Println("Failed to execute iptables command:", cmd, err)
			}
		}

		log.Printf("✅ Authorized IP: %s, MAC: %s", ip, mac)
		c.HTML(http.StatusOK, "portal.html", gin.H{"message": "You are now connected to the Internet!"})
	})

	// Function to test the status of connected devices and to remove their IP address from Redis and iptables
	go func() {
		for {
			keys, _ := rdb.Keys(ctx, "IP:*").Result()

			for _, k := range keys {
				ip := strings.TrimPrefix(k, "IP:")

				// Check ARP table for current status
				out, _ := exec.Command("bash", "-c",
					fmt.Sprintf("ip neigh | grep '%s' | awk '{print $NF}'", ip)).Output()
				status := strings.TrimSpace(string(out))

				// If device disappeared or unreachable
				if status == "" || status == "FAILED" || status == "INCOMPLETE" {
					cleanupDevice(ip)
				}
			}

			time.Sleep(5 * time.Second)
		}
	}()

	// Admin: list authorized IPs

	router.GET("/admin", func(c *gin.Context) {
		c.HTML(http.StatusOK, "admin.html", nil)
	})

	// Go to http://192.168.10.1:8080/admin to view connected devices
	router.GET("/admin/data", func(c *gin.Context) {
		devices := []gin.H{}

		// 1️⃣ Add authorized devices from Redis
		keys, _ := rdb.Keys(ctx, "IP:*").Result()
		for _, k := range keys {
			ip := strings.TrimPrefix(k, "IP:")
			mac := rdb.Get(ctx, k).Val()
			hostname := getHostname(ip)
			devices = append(devices, gin.H{
				"hostname": hostname,
				"ip":       ip,
				"mac":      mac,
			})
		}

		// 2️⃣ Scan ARP table for all connected devices
		out, _ := exec.Command("bash", "-c", "ip neigh show | grep -v FAILED").Output()
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			ip := fields[0]
			mac := fields[4]

			// Skip if already in devices
			exists := false
			for _, d := range devices {
				if d["ip"] == ip {
					exists = true
					break
				}
			}
			if exists {
				continue
			}

			hostname := getHostname(ip)
			devices = append(devices, gin.H{
				"hostname": hostname,
				"ip":       ip,
				"mac":      mac,
			})
		}

		c.JSON(200, gin.H{"devices": devices})
	})

	// Kick a device
	router.POST("/admin/kick/:ip", func(c *gin.Context) {
		ip := c.Param("ip")

		// Remove iptables rules
		cleanup := []string{
			fmt.Sprintf("iptables -t nat -D CAPTIVE_PORTAL -s %s -j RETURN 2>/dev/null", ip),
			fmt.Sprintf("iptables -D FORWARD -i wlan1 -s %s -j ACCEPT 2>/dev/null", ip),
		}
		for _, cmd := range cleanup {
			exec.Command("bash", "-c", cmd).Run()
		}

		// Delete only the IP entry
		mac := rdb.Get(ctx, "IP:"+ip).Val()
		rdb.Del(ctx, "IP:"+ip)

		c.JSON(200, gin.H{
			"status": "kicked",
			"ip":     ip,
			"mac":    mac,
		})
	})

	router.Run("0.0.0.0:8080")
}
