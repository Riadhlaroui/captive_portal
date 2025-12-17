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

const IPSET_NAME = "allowed_users"

func initIPSet() {
	exec.Command("ipset", "create", IPSET_NAME, "hash:ip", "-exist").Run()
}

func authorizeIP(ip string) error {
	log.Printf("🔓 Authorizing IP: %s", ip)
	return exec.Command("ipset", "add", IPSET_NAME, ip, "-exist").Run()
}

func kickIP(ip string) error {
	log.Printf("🔒 Kicking IP: %s", ip)
	return exec.Command("ipset", "del", IPSET_NAME, ip, "-exist").Run()
}

func isIPActive(ip string) bool {
	err := exec.Command("ipset", "test", IPSET_NAME, ip).Run()
	return err == nil
}

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
	cmd := exec.Command("bash", "-c", fmt.Sprintf("avahi-resolve -a %s 2>/dev/null | awk '{print $2}'", ip))
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		return strings.TrimSpace(string(out))
	}

	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	return "unknown"
}

func cleanupDevice(ip string) {
	mac := rdb.Get(ctx, "IP:"+ip).Val()

	kickIP(ip)

	if mac != "" {
		exec.Command("hostapd_cli", "-i", "wlan1", "deauthenticate", mac).Run()
		exec.Command("ip", "neigh", "del", ip, "dev", "wlan1").Run()
	}

	// Clean Redis
	rdb.Del(ctx, "IP:"+ip)
	rdb.Del(ctx, "MAC:"+mac)
	rdb.Del(ctx, "NAME:"+mac)

	log.Printf("🛑 Device cleaned up: IP=%s MAC=%s", ip, mac)
}

func redirectPortal(c *gin.Context) {
	c.Redirect(302, "http://192.168.10.1:8080/")
}

func main() {
	initIPSet()

	router := gin.Default()
	router.LoadHTMLGlob("templates/*.html")

	// Main Page
	router.GET("/", func(c *gin.Context) {
		c.HTML(200, "portal.html", nil)
	})

	// Captive Portal Detection
	router.GET("/generate_204", redirectPortal)
	router.GET("/gen_204", redirectPortal)
	router.GET("/hotspot-detect.html", redirectPortal)
	router.GET("/library/test/success.html", redirectPortal)
	router.GET("/ncsi.txt", func(c *gin.Context) { c.Redirect(302, "/") })
	router.GET("/connecttest.txt", redirectPortal)
	router.GET("/checkconnectivity.txt", redirectPortal)

	// AUTHORIZATION
	router.POST("/authorize", func(c *gin.Context) {
		ip := c.ClientIP()
		if ip == "" {
			c.HTML(http.StatusOK, "portal.html", gin.H{"error": "Unable to detect IP"})
			return
		}

		mac, err := getMAC(ip)
		if err != nil {
			log.Printf("Warning: Could not get MAC for %s", ip)
		} else {
			mac = strings.ToLower(mac)
		}

		name := getDHCPName(ip)
		if mac != "" {
			rdb.Set(ctx, "NAME:"+mac, name, 24*time.Hour)
			rdb.Set(ctx, "MAC:"+mac, "allowed", 24*time.Hour)
			rdb.Set(ctx, "IP:"+ip, mac, 24*time.Hour)
		}

		if err := authorizeIP(ip); err != nil {
			log.Println("Error adding to ipset:", err)
			c.HTML(http.StatusOK, "portal.html", gin.H{"error": "System Error. Try again."})
			return
		}

		c.HTML(http.StatusOK, "portal.html", gin.H{"message": "Connected! You are now online."})
	})

	// BACKGROUND WATCHDOG
	go func() {
		for {
			keys, _ := rdb.Keys(ctx, "IP:*").Result()
			for _, k := range keys {
				ip := strings.TrimPrefix(k, "IP:")

				out, _ := exec.Command("bash", "-c", fmt.Sprintf("ip neigh show %s", ip)).Output()
				state := string(out)

				if state == "" || strings.Contains(state, "FAILED") {
					cleanupDevice(ip)
				}
			}
			time.Sleep(5 * time.Second)
		}
	}()

	// ADMIN DASHBOARD
	router.GET("/admin", func(c *gin.Context) {
		c.HTML(http.StatusOK, "admin.html", nil)
	})

	// Get List of Connected Devices
	router.GET("/admin/data", func(c *gin.Context) {
		var devices []gin.H

		// Scan Redis for all known IP mappings
		iter := rdb.Scan(ctx, 0, "IP:*", 200).Iterator()

		for iter.Next(ctx) {
			key := iter.Val() // e.g., "IP:192.168.10.5"
			ip := strings.TrimPrefix(key, "IP:")

			mac := rdb.Get(ctx, key).Val()
			name := rdb.Get(ctx, "NAME:"+mac).Val()

			hostname := getHostnameCached(ip)

			active := isIPActive(ip)

			devices = append(devices, gin.H{
				"name":     name,
				"hostname": hostname,
				"ip":       ip,
				"mac":      mac,
				"active":   active,
			})
		}

		c.JSON(200, gin.H{"devices": devices})
	})

	// Kick a user
	router.POST("/admin/kick/:ip", func(c *gin.Context) {
		ip := c.Param("ip")

		cleanupDevice(ip)

		c.JSON(200, gin.H{
			"status": "kicked",
			"ip":     ip,
		})
	})

	// Start Server
	log.Println("🚀 Captive Portal Service Started on :8080")
	router.Run("0.0.0.0:8080")
}
