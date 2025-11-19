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
		ip, _, _ := net.SplitHostPort(c.Request.RemoteAddr)
		ip = strings.TrimSpace(ip)
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

		// Example: check if MAC is already authorized
		allowed, _ := rdb.Get(ctx, "MAC:"+mac).Result()
		if allowed == "allowed" {
			allowIP(ip)
			c.HTML(http.StatusOK, "portal.html", gin.H{"message": "You are already authorized."})
			return
		}

		// Save MAC in Redis
		rdb.Set(ctx, "MAC:"+mac, "allowed", 24*time.Hour)

		// Save IP too so iptables knows what to free
		rdb.Set(ctx, "IP:"+ip, mac, 24*time.Hour)

		// Whitelist the IP
		allowIP(ip)

		c.HTML(http.StatusOK, "portal.html", gin.H{"message": "You are now connected!"})

		// Allow this IP through captive portal
		// Use -C to check if rule exists first
		cmds := []string{
			fmt.Sprintf("iptables -t nat -C CAPTIVE_PORTAL -s %s -j RETURN 2>/dev/null || iptables -t nat -I CAPTIVE_PORTAL 1 -s %s -j RETURN", ip, ip),
			fmt.Sprintf("iptables -I FORWARD -i wlan1 -s %s -j ACCEPT", ip),
			fmt.Sprintf("iptables -t nat -D PREROUTING -i wlan1 -p udp --dport 53 -s %s -j DNAT --to-destination 192.168.10.1 2>/dev/null", ip), // remove DNS hijack
			"iptables -D FORWARD -i wlan1 -p tcp --dport 443 -j REJECT 2>/dev/null || true",                                                     // remove HTTPS block temporarily
		}

		for _, cmd := range cmds {
			if err := exec.Command("bash", "-c", cmd).Run(); err != nil {
				log.Println("Failed to execute iptables command:", cmd, err)
			}
		}

		log.Printf("✅ Authorized IP: %s", ip)
		c.HTML(http.StatusOK, "portal.html", gin.H{"message": "You are now connected to the Internet!"})
	})

	// Admin: list authorized IPs
	router.GET("/admin", func(c *gin.Context) {
		keys, _ := rdb.Keys(ctx, "IP:*").Result()
		ips := []string{}
		for _, k := range keys {
			ips = append(ips, k[3:]) // remove "IP:" prefix
		}
		c.JSON(200, gin.H{"authorized_ips": ips})
	})

	router.Run("0.0.0.0:8080")
}
