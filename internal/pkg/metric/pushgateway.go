// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2018-2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package metric

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/opencontainers/runc/libcontainer/cgroups"
)

const (
	sock    = "/tmp/pushgateway/socket"
	baseUrl = "http://unix"
)

type PushGateway struct {
	*http.Client
}

type ContainerMetric struct {
	Container *ContainerInfo `json:"container,omitempty"`
	Metric    *Metric        `json:"metric,omitempty"`
	TimeStamp time.Time      `json:"timestamp,omitempty"`
}

type ContainerInfo struct {
	Id  string `json:"id,omitempty"`
	Exe string `json:"exe,omitempty"`
}

type Metric struct {
	Cpu     *cgroups.CpuStats     `json:"cpu,omitempty`
	CpuSet  *cgroups.CPUSetStats  `json:"cpu_set,omitempty"`
	Mem     *cgroups.MemoryStats  `json:"mem,omitempty"`
	Page    *cgroups.PageStats    `json:"page,omitempty"`
	Pid     *cgroups.PidsStats    `json:"pid,omitempty"`
	Rdma    *cgroups.RdmaStats    `json:"rdma,omitempty"`
	Hugetlb *cgroups.HugetlbStats `json:"hugetlb,omitempty"`
	Blkio   *cgroups.BlkioStats   `json:"blkio,omitempty"`
}

func NewPushGateway(socketPath string) *PushGateway {
	return &PushGateway{
		&http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", socketPath)
				},
			},
		},
	}
}

type requestCreator func(*PushGateway, string, []byte) error

func (p *PushGateway) Push(metric *ContainerMetric) error {
	data, err := marshalMetric(metric)
	if err != nil {
		return err
	}
	return pushRequest()(p, "/metrics/job/"+metric.Container.Id, data)
}

func pushRequest() requestCreator {
	return func(p *PushGateway, s string, b []byte) error {
		req, err := http.NewRequest("POST", baseUrl+"/metrics/job", bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "plain/text")

		rep, err := p.Do(req)
		if err != nil {
			return err
		}
		if rep.StatusCode != http.StatusOK {
			return fmt.Errorf("request received non-200 code: %d", rep.StatusCode)
		}

		return nil
	}
}

func writeBuffer(buffer *bytes.Buffer, data interface{}) error {
	d, err := json.Marshal(data)
	if err != nil {
		return err
	}
	d = append(d, " 0\n"...)
	_, err = buffer.Write(d)
	if err != nil {
		return err
	}
	return nil
}

func marshalMetric(metric *ContainerMetric) ([]byte, error) {
	var buffer bytes.Buffer
	_, err := buffer.WriteString(metric.Container.Exe + " 0\n")
	if err != nil {
		return buffer.Bytes(), err
	}

	err = writeBuffer(&buffer, metric.Metric)
	if err != nil {
		return buffer.Bytes(), err
	}

	return buffer.Bytes(), nil
}
