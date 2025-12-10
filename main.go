package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
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

// Constant for the IP set name (must match your startup script)
const IPSET_NAME = "allowed_users"

// --- IPSET HELPER FUNCTIONS ---

// initIPSet ensures the set exists when the program starts
func initIPSet() {
	// silently create if not exists
	exec.Command("ipset", "create", IPSET_NAME, "hash:ip", "-exist").Run()
}

// authorizeIP adds an IP to the allowed list (Instant internet access)
func authorizeIP(ip string) error {
	log.Printf("🔓 Authorizing IP: %s", ip)
	return exec.Command("ipset", "add", IPSET_NAME, ip, "-exist").Run()
}

// kickIP removes an IP from the allowed list (Instant block)
func kickIP(ip string) error {
	log.Printf("🔒 Kicking IP: %s", ip)
	return exec.Command("ipset", "del", IPSET_NAME, ip, "-exist").Run()
}

// isIPActive checks if the IP is currently in the ipset
func isIPActive(ip string) bool {
	err := exec.Command("ipset", "test", IPSET_NAME, ip).Run()
	return err == nil // err is nil if the IP is in the set
}

// --- UTILITY FUNCTIONS ---

func getHostnameCached(ip string) string {
	h := rdb.Get(ctx, "HOST:"+ip).Val()
	if h != "" {
		return h
	}
	h = getHostname(ip)
	rdb.Set(ctx, "HOST:"+ip, h, 24*time.Hour)
	return h
}

func getDHCPName(ip string) string {
	data, err := os.ReadFile("/var/lib/misc/dnsmasq.leases")
	if err != nil {
		return "unknown"
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[2] == ip {
			return fields[3]
		}
	}
	return "unknown"
}

func getMAC(ip string) (string, error) {
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

func getHostname(ip string) string {
	// Try mDNS
	cmd := exec.Command("bash", "-c", fmt.Sprintf("avahi-resolve -a %s 2>/dev/null | awk '{print $2}'", ip))
	out, err := cmd.Output()
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

// cleanupDevice handles the logic of removing a user completely
func cleanupDevice(ip string) {
	mac := rdb.Get(ctx, "IP:"+ip).Val()

	// 1. Remove from Firewall (Block Internet)
	kickIP(ip)

	// 2. Optional: Force WiFi disconnect (Deauth)
	if mac != "" {
		exec.Command("hostapd_cli", "-i", "wlan1", "deauthenticate", mac).Run()
		exec.Command("ip", "neigh", "del", ip, "dev", "wlan1").Run()
	}

	// 3. Clean Redis
	rdb.Del(ctx, "IP:"+ip)
	rdb.Del(ctx, "MAC:"+mac)
	rdb.Del(ctx, "NAME:"+mac)

	log.Printf("🛑 Device cleaned up: IP=%s MAC=%s", ip, mac)
}

func redirectPortal(c *gin.Context) {
	// Always redirect to the gateway IP, not just "/"
	// This ensures they land on the portal page even if they requested google.com
	c.Redirect(302, "http://192.168.10.1:8080/")
}

// --- MAIN ---

func main() {
	// Ensure the IPSet exists on startup
	initIPSet()

	router := gin.Default()
	router.LoadHTMLGlob("templates/*.html")

	// Serve Static Assets (if you have CSS/JS files)
	// router.Static("/static", "./static")

	// Main Page
	router.GET("/", func(c *gin.Context) {
		c.HTML(200, "portal.html", nil)
	})

	// --- Captive Portal Detection (OS Checks) ---
	router.GET("/generate_204", redirectPortal)
	router.GET("/gen_204", redirectPortal)
	router.GET("/hotspot-detect.html", redirectPortal)
	router.GET("/library/test/success.html", redirectPortal)
	router.GET("/ncsi.txt", func(c *gin.Context) { c.Redirect(302, "/") })
	router.GET("/connecttest.txt", redirectPortal)
	router.GET("/checkconnectivity.txt", redirectPortal)

	// --- AUTHORIZATION HANDLER ---
	router.POST("/authorize", func(c *gin.Context) {
		ip := c.ClientIP()
		if ip == "" {
			c.HTML(http.StatusOK, "portal.html", gin.H{"error": "Unable to detect IP"})
			return
		}

		mac, err := getMAC(ip)
		if err != nil {
			// Fallback: If we can't get MAC, we can still auth by IP,
			// but tracking will be harder.
			log.Printf("Warning: Could not get MAC for %s", ip)
		} else {
			mac = strings.ToLower(mac)
		}

		// 1. Store/Update User Info in Redis
		name := getDHCPName(ip)
		if mac != "" {
			rdb.Set(ctx, "NAME:"+mac, name, 24*time.Hour)
			rdb.Set(ctx, "MAC:"+mac, "allowed", 24*time.Hour)
			rdb.Set(ctx, "IP:"+ip, mac, 24*time.Hour)
		}

		// 2. ENABLE INTERNET ACCESS (The magic single command)
		if err := authorizeIP(ip); err != nil {
			log.Println("Error adding to ipset:", err)
			c.HTML(http.StatusOK, "portal.html", gin.H{"error": "System Error. Try again."})
			return
		}

		c.HTML(http.StatusOK, "portal.html", gin.H{"message": "Connected! You are now online."})
	})

	// --- BACKGROUND WATCHDOG ---
	// Checks for disconnected devices every 15 seconds
	go func() {
		for {
			keys, _ := rdb.Keys(ctx, "IP:*").Result()
			for _, k := range keys {
				ip := strings.TrimPrefix(k, "IP:")

				// Check ARP state
				out, _ := exec.Command("bash", "-c", fmt.Sprintf("ip neigh show %s", ip)).Output()
				state := string(out)

				// If ARP entry is missing or FAILED, device is gone
				if state == "" || strings.Contains(state, "FAILED") {
					cleanupDevice(ip)
				}
			}
			time.Sleep(5 * time.Second)
		}
	}()

	// --- ADMIN DASHBOARD ---
	router.GET("/admin", func(c *gin.Context) {
		c.HTML(http.StatusOK, "admin.html", nil)
	})

	// API: Get List of Connected Devices
	router.GET("/admin/data", func(c *gin.Context) {
		var devices []gin.H

		// Scan Redis for all known IP mappings
		iter := rdb.Scan(ctx, 0, "IP:*", 200).Iterator()

		for iter.Next(ctx) {
			key := iter.Val() // e.g., "IP:192.168.10.5"
			ip := strings.TrimPrefix(key, "IP:")

			mac := rdb.Get(ctx, key).Val()
			name := rdb.Get(ctx, "NAME:"+mac).Val()

			// Resolve Hostname (cached)
			hostname := getHostnameCached(ip)

			// Check if they are truly active in the Firewall
			active := isIPActive(ip)

			devices = append(devices, gin.H{
				"name":     name,
				"hostname": hostname,
				"ip":       ip,
				"mac":      mac,
				"active":   active, // Boolean for frontend badge (Green/Red)
			})
		}

		c.JSON(200, gin.H{"devices": devices})
	})

	// API: Kick a user
	router.POST("/admin/kick/:ip", func(c *gin.Context) {
		ip := c.Param("ip")

		// Use our cleanup function to remove from Redis + Firewall
		cleanupDevice(ip)

		c.JSON(200, gin.H{
			"status": "kicked",
			"ip":     ip,
		})
	})

	// Start Server
	// Ensure this matches PORTAL_PORT in your bash script
	log.Println("🚀 Captive Portal Service Started on :8080")
	router.Run("0.0.0.0:8080")
}
