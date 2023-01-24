package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"
	"gopkg.in/yaml.v2"

	grpc_health_v1 "github.com/target/strelka/src/go/api/health"
	"github.com/target/strelka/src/go/api/strelka"
	"github.com/target/strelka/src/go/pkg/rpc"
	"github.com/target/strelka/src/go/pkg/structs"
)

type coord struct {
	cli *redis.Client
}

type gate struct {
	cli *redis.Client
	ttl time.Duration
}

type server struct {
	coordinator coord
	gatekeeper  *gate
	responses   chan<- *strelka.ScanResponse
}

type request struct {
	Attributes *strelka.Attributes `json:"attributes,omitempty"`
	Client     string              `json:"client,omitempty"`
	Id         string              `json:"id,omitempty"`
	Source     string              `json:"source,omitempty"`
	Time       int64               `json:"time,omitempty"`
}

func (s *server) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}

func (s *server) ScanFile(stream strelka.Frontend_ScanFileServer) error {
	deadline, ok := stream.Context().Deadline()
	if ok == false {
		return nil
	}

	hash := sha256.New()
	id := uuid.New().String()
	keyd := fmt.Sprintf("data:%v", id)
	keye := fmt.Sprintf("event:%v", id)
	keyo := fmt.Sprintf("org_id:%s", id)

	var attr *strelka.Attributes
	var req *strelka.Request

	p := s.coordinator.cli.Pipeline()
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if attr == nil {
			attr = in.Attributes
		}

		if req == nil {
			req = in.Request
		}

		if attr.OrgID != "" {
			p.Set(stream.Context(), keyo, attr.OrgID, time.Until(deadline))
		}

		if len(in.Data) > 0 {
			hash.Write(in.Data)
			p.RPush(stream.Context(), keyd, in.Data)
		}

		if _, err := p.Exec(stream.Context()); err != nil {
			return err
		}
	}

	if req == nil || attr == nil {
		return nil
	}
	if req.Id == "" {
		req.Id = id
	}

	sha := fmt.Sprintf("hash:%x", hash.Sum(nil))
	em := make(map[string]interface{})
	em["request"] = request{
		Attributes: attr,
		Client:     req.Client,
		Id:         req.Id,
		Source:     req.Source,
		Time:       time.Now().Unix(),
	}

	if req.Gatekeeper && s.gatekeeper != nil {
		lrange := s.gatekeeper.cli.LRange(stream.Context(), sha, 0, -1).Val()
		if len(lrange) > 0 {
			for _, e := range lrange {
				if err := json.Unmarshal([]byte(e), &em); err != nil {
					return err
				}

				event, err := json.Marshal(em)
				if err != nil {
					return err
				}

				resp := &strelka.ScanResponse{
					Id:    req.Id,
					Event: string(event),
				}

				s.responses <- resp
				if err := stream.Send(resp); err != nil {
					return err
				}
			}

			if err := s.coordinator.cli.Del(stream.Context(), keyd).Err(); err != nil {
				return err
			}

			return nil
		}
	}

	if err := s.coordinator.cli.ZAdd(
		stream.Context(),
		"tasks",
		&redis.Z{
			Score:  float64(deadline.Unix()),
			Member: id,
		},
	).Err(); err != nil {
		return err
	}

	var tx *redis.Pipeliner
	if s.gatekeeper != nil {
		pipeliner := s.gatekeeper.cli.TxPipeline()
		tx = &pipeliner
		(*tx).Del(stream.Context(), sha)
	}

	for {
		if err := stream.Context().Err(); err != nil {
			return err
		}

		res, err := s.coordinator.cli.BLPop(stream.Context(), 5*time.Second, keye).Result()
		if err != nil {
			if err != redis.Nil {
				// Delay to prevent fast looping over errors
				time.Sleep(250 * time.Millisecond)
			}
			continue
		}
		// first element will be the name of queue/event, second element is event itself
		if len(res) != 2 {
			return fmt.Errorf("unexpected result length")
		}

		lpop := res[1]
		if lpop == "FIN" {
			break
		}

		if tx != nil {
			(*tx).RPush(stream.Context(), sha, lpop)
		}
		if err := json.Unmarshal([]byte(lpop), &em); err != nil {
			return err
		}

		event, err := json.Marshal(em)
		if err != nil {
			return err
		}

		resp := &strelka.ScanResponse{
			Id:    req.Id,
			Event: string(event),
		}

		s.responses <- resp
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	if tx != nil {
		(*tx).Expire(stream.Context(), sha, s.gatekeeper.ttl)
		if _, err := (*tx).Exec(stream.Context()); err != nil {
			return err
		}
	}

	return nil
}

func (s *server) CompileYara(stream strelka.Frontend_CompileYaraServer) error {
	var req *strelka.Request

	deadline, ok := stream.Context().Deadline()
	if ok == false {
		return nil
	}

	id := uuid.New().String()
	p := s.coordinator.cli.Pipeline()

	keyYaraCompile := fmt.Sprintf("yara:compile:%s", id)
	keyYaraCompileDone := fmt.Sprintf("yara:compile:done:%s", id)

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if req == nil {
			req = in.Request
		}

		if len(in.Data) > 0 {
			// Send for compilation
			p.RPush(stream.Context(), keyYaraCompile, in.Data)
			p.ExpireAt(stream.Context(), keyYaraCompile, deadline)

			if _, err := p.Exec(stream.Context()); err != nil {
				return err
			}
		}
	}

	// skip gatekeeper, we're not sending it

	// send task to backend
	if err := s.coordinator.cli.ZAdd(
		stream.Context(),
		"tasks_compile_yara",
		&redis.Z{
			Score:  float64(deadline.Unix()),
			Member: id,
		},
	).Err(); err != nil {
		return err
	}

	var errMsg string

	for {
		if err := stream.Context().Err(); err != nil {
			return fmt.Errorf("context closed: %w", err)
		}

		res, err := s.coordinator.cli.BLPop(
			stream.Context(),
			5*time.Second,
			keyYaraCompileDone,
		).Result()
		if err != nil {
			if err != redis.Nil {
				// Delay to prevent fast looping over errors
				log.Printf("err: %v\n", err)
				time.Sleep(250 * time.Millisecond)
			}
			continue
		}

		if res[1] == "FIN" {
			break
		}

		if strings.HasPrefix(res[1], "ERROR:") {
			errMsg = strings.Replace(res[1], "ERROR:", "", 1)
			break
		}
	}

	resp := &strelka.CompileYaraResponse{
		Ok:    errMsg == "",
		Error: errMsg,
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

	return nil
}

func (s *server) SyncYara(stream strelka.Frontend_SyncYaraServer) error {
	var orgID string
	var req *strelka.Request

	deadline, ok := stream.Context().Deadline()
	if ok == false {
		return nil
	}

	id := uuid.New().String()
	p := s.coordinator.cli.Pipeline()

	var keyYaraHash string
	keyOrgID := fmt.Sprintf("org_id:%s", id)
	keyYaraSync := fmt.Sprintf("yara:compile_and_sync:%s", id)
	keyYaraSyncDone := fmt.Sprintf("yara:compile_and_sync:done:%s", id)

	log.Println("sync yara")
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if req == nil {
			req = in.Request
		}

		if orgID == "" {
			orgID = in.OrgID
		}

		keyYaraHash = fmt.Sprintf("yara:hash:%s", orgID)
		p.Set(stream.Context(), keyOrgID, orgID, time.Until(deadline))

		if len(in.Data) > 0 {
			for _, inData := range in.Data {
				outData, err := json.Marshal(*inData)
				if err != nil {
					return err
				}

				// Send for compilation
				p.RPush(stream.Context(), keyYaraSync, outData)
				p.ExpireAt(stream.Context(), keyYaraSync, deadline)
			}

			if _, err := p.Exec(stream.Context()); err != nil {
				return err
			}
		}
	}

	// skip gatekeeper, we're not sending it

	// send task to backend
	if err := s.coordinator.cli.ZAdd(
		stream.Context(),
		"tasks_compile_and_sync_yara",
		&redis.Z{
			Score:  float64(deadline.Unix()),
			Member: id,
		},
	).Err(); err != nil {
		return err
	}

	var errMsg string

	for {
		if err := stream.Context().Err(); err != nil {
			return fmt.Errorf("context closed: %w", err)
		}

		res, err := s.coordinator.cli.BLPop(
			stream.Context(),
			5*time.Second,
			keyYaraSyncDone,
		).Result()
		if err != nil {
			if err != redis.Nil {
				// Delay to prevent fast looping over errors
				log.Printf("err: %v\n", err)
				time.Sleep(250 * time.Millisecond)
			}
			continue
		}

		if res[1] == "FIN" {
			break
		}

		if strings.HasPrefix(res[1], "ERROR:") {
			errMsg = strings.Replace(res[1], "ERROR:", "", 1)
			break
		}
	}

	resp := &strelka.SyncYaraResponse{}

	resp.Synced = 0
	hash, err := s.coordinator.cli.Get(stream.Context(), keyYaraHash).Result()
	if err != nil {
		return fmt.Errorf("getting hash: %w", err)
	}

	synced, err := s.coordinator.cli.Get(stream.Context(), fmt.Sprintf("yara:synced:%s", id)).Result()
	if err != nil {
		return fmt.Errorf("getting sync count: %w", err)
	}

	nSynced, err := strconv.Atoi(synced)
	if err != nil {
		// bye bye bye
		return err
	}

	resp.Hash = []byte(hash)
	resp.Error = errMsg
	resp.Synced = int32(nSynced)

	if err := stream.Send(resp); err != nil {
		return err
	}

	return nil
}

func (s *server) ShouldUpdateYara(stream strelka.Frontend_ShouldUpdateYaraServer) error {
	var keyYaraHash string
	var orgID string
	var hash []byte

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if orgID == "" {
			orgID = in.OrgID
		}

		if len(hash) == 0 {
			hash = in.Hash
		}

		keyYaraHash = fmt.Sprintf("yara:hash:%s", orgID)
	}

	var currentHash string

	res := s.coordinator.cli.Get(stream.Context(), keyYaraHash)
	err := res.Err()
	if err == redis.Nil {
		// do nothing
	} else if err != nil {
		return err
	}

	currentHash, err = res.Result()
	if err != nil {
		return err
	}

	if err := stream.Send(&strelka.ShouldUpdateYaraResponse{
		Ok: string(hash) != currentHash,
	}); err != nil {
		return err
	}

	return nil
}

func main() {
	confPath := flag.String(
		"c",
		"/etc/strelka/frontend.yaml",
		"path to frontend config",
	)
	flag.Parse()

	confData, err := ioutil.ReadFile(*confPath)
	if err != nil {
		log.Fatalf("failed to read config file %s: %v", *confPath, err)
	}

	var conf structs.Frontend
	err = yaml.Unmarshal(confData, &conf)
	if err != nil {
		log.Fatalf("failed to load config data: %v", err)
	}

	listen, err := net.Listen("tcp", conf.Server)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	responses := make(chan *strelka.ScanResponse, 100)
	defer close(responses)
	if conf.Response.Log != "" {
		go func() {
			rpc.LogResponses(responses, conf.Response.Log)
		}()
		log.Printf("responses will be logged to %v", conf.Response.Log)
	} else if conf.Response.Report != 0 {
		go func() {
			rpc.ReportResponses(responses, conf.Response.Report)
		}()
		log.Printf("responses will be reported every %v", conf.Response.Report)
	} else {
		go func() {
			rpc.DiscardResponses(responses)
		}()
		log.Println("responses will be discarded")
	}

	cd := redis.NewClient(&redis.Options{
		Addr:        conf.Coordinator.Addr,
		DB:          conf.Coordinator.DB,
		PoolSize:    conf.Coordinator.Pool,
		ReadTimeout: conf.Coordinator.Read,
	})
	if err := cd.Ping(cd.Context()).Err(); err != nil {
		log.Fatalf("failed to connect to coordinator: %v", err)
	}

	var gatekeeper *gate
	if conf.Gatekeeper.Addr != "" {
		gk := redis.NewClient(&redis.Options{
			Addr:        conf.Gatekeeper.Addr,
			DB:          conf.Gatekeeper.DB,
			PoolSize:    conf.Gatekeeper.Pool,
			ReadTimeout: conf.Gatekeeper.Read,
		})
		if err := gk.Ping(gk.Context()).Err(); err != nil {
			log.Fatalf("failed to connect to gatekeeper: %v", err)
		}

		gatekeeper = &gate{
			cli: gk,
			ttl: conf.Gatekeeper.TTL,
		}
	}

	s := grpc.NewServer()
	opts := &server{
		coordinator: coord{
			cli: cd,
		},
		gatekeeper: gatekeeper,
		responses:  responses,
	}

	strelka.RegisterFrontendServer(s, opts)
	grpc_health_v1.RegisterHealthServer(s, opts)
	s.Serve(listen)
}
