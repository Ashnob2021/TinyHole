package xray

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"panel/database"
)

type statsResponse struct {
	Stat []struct {
		Name  string `json:"name"`
		Value int64  `json:"value"`
	}
}

type TrafficCollector struct {
	manager  *Manager
	mu       sync.Mutex
	previous map[int64]int64
}

func NewTrafficCollector(manager *Manager) *TrafficCollector {
	return &TrafficCollector{
		manager:  manager,
		previous: make(map[int64]int64),
	}
}

func (tc *TrafficCollector) Start() {
	go func() {
		log.Println("Traffic collector started")

		time.Sleep(5 * time.Second)

		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			tc.collect()
			<-ticker.C
		}
	}()
}

func (tc *TrafficCollector) collect() {
	rows, err := database.DB.Query(`
		SELECT id
		FROM clients
		WHERE enabled = 1
	`)
	if err != nil {
		log.Println("Traffic collector database error:", err)
		return
	}

	var clientIDs []int64

	for rows.Next() {
		var id int64

		if err := rows.Scan(&id); err != nil {
			log.Println("Traffic collector scan error:", err)
			continue
		}

		clientIDs = append(clientIDs, id)
	}

	if err := rows.Err(); err != nil {
		log.Println("Traffic collector rows error:", err)
	}

	rows.Close()

	for _, id := range clientIDs {

		up, down, err := queryUserTraffic(id)
		if err != nil {
			log.Printf(
				"Traffic stats query failed for client-%d: %v",
				id,
				err,
			)
			continue
		}

		current := up + down

		tc.mu.Lock()
		previous := tc.previous[id]

		var delta int64

		if current >= previous {
			delta = current - previous
		} else {
			// Xray restarted and counters reset.
			delta = current
		}

		tc.mu.Unlock()

		if delta > 0 {
			if err := tc.applyTraffic(id, delta); err != nil {
				log.Printf(
					"Failed to apply traffic for client-%d: %v",
					id,
					err,
				)
				continue
			}
		}

		tc.mu.Lock()
		tc.previous[id] = current
		tc.mu.Unlock()
	}
}

func (tc *TrafficCollector) ResetClient(id int64) {
	up, down, err := queryUserTraffic(id)

	if err != nil {
		log.Printf(
			"Failed to read Xray stats while resetting client-%d: %v",
			id,
			err,
		)

		tc.mu.Lock()
		delete(tc.previous, id)
		tc.mu.Unlock()

		return
	}

	current := up + down

	tc.mu.Lock()
	tc.previous[id] = current
	tc.mu.Unlock()
}

func queryUserTraffic(id int64) (int64, int64, error) {
	email := fmt.Sprintf("client-%d", id)

	cmd := exec.Command(
		"xray",
		"api",
		"statsquery",
		"--server=127.0.0.1:10085",
		"-pattern",
		"user>>>"+email+">>>traffic>>>",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, 0, err
	}

	var response statsResponse

	if err := json.Unmarshal(output, &response); err != nil {
		return 0, 0, err
	}

	var uplink int64
	var downlink int64

	for _, stat := range response.Stat {

		value := stat.Value

		if strings.HasSuffix(stat.Name, ">>>uplink") {
			uplink = value
		}

		if strings.HasSuffix(stat.Name, ">>>downlink") {
			downlink = value
		}
	}

	return uplink, downlink, nil
}

func (tc *TrafficCollector) applyTraffic(id int64, delta int64) error {

	var (
		used    int64
		limit   int64
		enabled int
		protocol string
	)

	err := database.DB.QueryRow(`
		SELECT
			traffic_used_bytes,
			traffic_limit_bytes,
			enabled,
			protocol
		FROM clients
		WHERE id = ?
	`, id).Scan(
		&used,
		&limit,
		&enabled,
		&protocol,
	)

	if err != nil {
		return err
	}

	if enabled == 0 {
		return nil
	}

	newUsed := used + delta

	_, err = database.DB.Exec(`
		UPDATE clients
		SET traffic_used_bytes = ?,
		    last_seen = CURRENT_TIMESTAMP
		WHERE id = ?
	`, newUsed, id)

	if err != nil {
		return err
	}

	// 0 = unlimited
	if limit > 0 && newUsed >= limit {

		log.Printf(
			"Client %d reached traffic limit (%d bytes). Disabling client.",
			id,
			limit,
		)

		_, err := database.DB.Exec(`
			UPDATE clients
			SET enabled = 0
			WHERE id = ?
		`, id)

		if err != nil {
			return err
		}

		// Remove the client from the running Xray process
		// without restarting Xray.
		if tc.manager != nil {

			email := fmt.Sprintf("client-%d", id)

			if err := tc.manager.RemoveClient(protocol, email); err != nil {
				return fmt.Errorf(
					"failed to hot-remove client-%d after quota reached: %w",
					id,
					err,
				)
			}

			log.Printf(
				"Client %d was hot-removed from Xray after reaching quota.",
				id,
			)
		}
	}

	return nil
}
