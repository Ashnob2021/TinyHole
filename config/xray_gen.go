package config

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

type Client struct {
	ID       int64
	UUID     string
	Password string
	Email    string
	Enabled  bool
}

func GenerateXrayConfig(clients []Client) ([]byte, error) {
	vlessClients := make([]map[string]interface{}, 0)
	trojanClients := make([]map[string]interface{}, 0)

	for _, client := range clients {
		if !client.Enabled {
			continue
		}

		if client.UUID != "" {
			vlessClients = append(vlessClients, map[string]interface{}{
				"id":    client.UUID,
				"email": client.Email,
				"level": 0,
			})
		}

		if client.Password != "" {
			trojanClients = append(trojanClients, map[string]interface{}{
				"password": client.Password,
				"email":    client.Email,
				"level":    0,
			})
		}
	}

	cfg := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},

		"api": map[string]interface{}{
			"tag": "api",
			"services": []string{
				"HandlerService",
				"StatsService",
			},
		},

		"stats": map[string]interface{}{},

		"policy": map[string]interface{}{
			"levels": map[string]interface{}{
				"0": map[string]interface{}{
					"statsUserUplink":   true,
					"statsUserDownlink": true,
					"statsUserOnline":   true,
				},
			},
		},

		"routing": map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"type": "field",
					"inboundTag": []string{
						"api",
					},
					"outboundTag": "api",
				},
			},
		},

		"inbounds": []interface{}{
			map[string]interface{}{
				"tag":      "api",
				"listen":   "127.0.0.1",
				"port":     10085,
				"protocol": "dokodemo-door",

				"settings": map[string]interface{}{
					"address": "127.0.0.1",
				},
			},

			map[string]interface{}{
				"tag":      "vless-ws",
				"listen":   "127.0.0.1",
				"port":     2097,
				"protocol": "vless",

				"settings": map[string]interface{}{
					"clients":    vlessClients,
					"decryption": "none",
				},

				"streamSettings": map[string]interface{}{
					"network":  "ws",
					"security": "none",

					"wsSettings": map[string]interface{}{
						"path": "/vless",
					},
				},
			},

			map[string]interface{}{
				"tag":      "trojan-ws",
				"listen":   "127.0.0.1",
				"port":     2098,
				"protocol": "trojan",

				"settings": map[string]interface{}{
					"clients": trojanClients,
				},

				"streamSettings": map[string]interface{}{
					"network":  "ws",
					"security": "none",

					"wsSettings": map[string]interface{}{
						"path": "/trojan",
					},
				},
			},
		},

		"outbounds": []interface{}{
			map[string]interface{}{
				"protocol": "freedom",
				"tag":      "direct",
			},
		},
	}

	return json.MarshalIndent(cfg, "", "  ")
}

func GenerateVlessConfig(sni, wsHost string) map[string]interface{} {
	id := uuid.New().String()

	return map[string]interface{}{
		"protocol": "vless",
		"settings": map[string]interface{}{
			"clients": []map[string]string{
				{"id": id},
			},
		},
		"streamSettings": map[string]interface{}{
			"network":  "ws",
			"security": "tls",
			"wsSettings": map[string]string{
				"path": "/vless",
				"host": wsHost,
			},
			"tlsSettings": map[string]string{
				"serverName": sni,
			},
		},
	}
}

func GenerateTrojanConfig(sni, wsHost string) map[string]interface{} {
	password := uuid.New().String()

	return map[string]interface{}{
		"protocol": "trojan",
		"settings": map[string]interface{}{
			"clients": []map[string]string{
				{"password": password},
			},
		},
		"streamSettings": map[string]interface{}{
			"network":  "ws",
			"security": "tls",
			"wsSettings": map[string]string{
				"path": "/trojan",
				"host": wsHost,
			},
			"tlsSettings": map[string]string{
				"serverName": sni,
			},
		},
	}
}

func ToJSON(cfg map[string]interface{}) (string, error) {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal error: %v", err)
	}

	return string(b), nil
}
