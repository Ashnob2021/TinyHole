package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"panel/config"
	"panel/database"
)

type Manager struct {
	mu  sync.Mutex
	cmd *exec.Cmd
}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.generateConfigLocked(); err != nil {
		return err
	}

	return m.startLocked()
}

func (m *Manager) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd != nil && m.cmd.Process != nil {
		log.Println("Stopping Xray...")

		_ = m.cmd.Process.Kill()
		_, _ = m.cmd.Process.Wait()

		m.cmd = nil
	}

	if err := m.generateConfigLocked(); err != nil {
		return err
	}

	log.Println("Starting Xray with updated configuration...")

	return m.startLocked()
}

func (m *Manager) startLocked() error {
	cmd := exec.CommandContext(
		context.Background(),
		"xray",
		"run",
		"-c",
		"config/xray.json",
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start Xray: %w", err)
	}

	m.cmd = cmd

	log.Println("Xray started")

	return nil
}

// AddClient adds a client to the running Xray process without restarting it.
func (m *Manager) AddClient(protocolName, email, credential string) error {
	return m.alterClient(protocolName, email, credential, true)
}

// RemoveClient removes a client from the running Xray process without restarting it.
func (m *Manager) RemoveClient(protocolName, email string) error {
	return m.alterClient(protocolName, email, "", false)
}

func (m *Manager) alterClient(protocolName, email, credential string, add bool) error {
	inboundTag, err := inboundTagForProtocol(protocolName)
	if err != nil {
		return err
	}

	conn, err := grpc.Dial(
		"127.0.0.1:10085",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to Xray API: %w", err)
	}
	defer conn.Close()

	client := command.NewHandlerServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var operation *serial.TypedMessage

	if add {
		account, err := accountForProtocol(protocolName, credential)
		if err != nil {
			return err
		}

		operation = serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Email:   email,
				Level:   0,
				Account: account,
			},
		})
	} else {
		operation = serial.ToTypedMessage(&command.RemoveUserOperation{
			Email: email,
		})
	}

	_, err = client.AlterInbound(
		ctx,
		&command.AlterInboundRequest{
			Tag:       inboundTag,
			Operation: operation,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"Xray hot update failed for %s client %s: %w",
			protocolName,
			email,
			err,
		)
	}

	if add {
		log.Printf(
			"Xray hot update: added %s client %s",
			protocolName,
			email,
		)
	} else {
		log.Printf(
			"Xray hot update: removed %s client %s",
			protocolName,
			email,
		)
	}

	return nil
}

func inboundTagForProtocol(protocolName string) (string, error) {
	switch protocolName {
	case "vless":
		return "vless-ws", nil
	case "trojan":
		return "trojan-ws", nil
	default:
		return "", fmt.Errorf("unsupported protocol: %s", protocolName)
	}
}

func accountForProtocol(protocolName, credential string) (*serial.TypedMessage, error) {
	switch protocolName {
	case "vless":
		return serial.ToTypedMessage(&vless.Account{
			Id: credential,
		}), nil

	case "trojan":
		return serial.ToTypedMessage(&trojan.Account{
			Password: credential,
		}), nil

	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocolName)
	}
}

func (m *Manager) generateConfigLocked() error {
	rows, err := database.DB.Query(`
		SELECT id, uuid, password, enabled
		FROM clients
		ORDER BY id
	`)
	if err != nil {
		return fmt.Errorf("failed to query clients: %w", err)
	}
	defer rows.Close()

	var clients []config.Client

	for rows.Next() {
		var (
			id       int64
			uuid     string
			password string
			enabled  int
		)

		if err := rows.Scan(&id, &uuid, &password, &enabled); err != nil {
			return fmt.Errorf("failed to read client: %w", err)
		}

		clients = append(clients, config.Client{
			ID:       id,
			UUID:     uuid,
			Password: password,
			Email:    fmt.Sprintf("client-%d", id),
			Enabled:  enabled == 1,
		})
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed while reading clients: %w", err)
	}

	data, err := config.GenerateXrayConfig(clients)
	if err != nil {
		return fmt.Errorf("failed to generate Xray config: %w", err)
	}

	var pretty json.RawMessage
	if err := json.Unmarshal(data, &pretty); err != nil {
		return fmt.Errorf("invalid generated Xray config: %w", err)
	}

	if err := os.WriteFile("config/xray.json", data, 0644); err != nil {
		return fmt.Errorf("failed to write Xray config: %w", err)
	}

	enabledCount := 0
	for _, client := range clients {
		if client.Enabled {
			enabledCount++
		}
	}

	log.Printf(
		"Xray configuration updated: %d client(s), %d enabled",
		len(clients),
		enabledCount,
	)

	return nil
}
