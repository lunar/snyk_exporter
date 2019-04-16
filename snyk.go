package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"

	"github.com/prometheus/common/log"
)

type client struct {
	httpClient *http.Client
	token      string
	baseURL    string
}

func (c *client) getOrganizations() (orgsResponse, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/orgs", c.baseURL), nil)
	if err != nil {
		return orgsResponse{}, err
	}
	response, err := c.do(req)
	if err != nil {
		return orgsResponse{}, err
	}
	var orgs orgsResponse
	err = json.NewDecoder(response.Body).Decode(&orgs)
	if err != nil {
		return orgsResponse{}, err
	}
	return orgs, nil
}

func (c *client) getProjects(organization string) (projectsResponse, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/org/%s/projects", c.baseURL, organization), nil)
	if err != nil {
		return projectsResponse{}, err
	}
	response, err := c.do(req)
	if err != nil {
		return projectsResponse{}, err
	}
	var projects projectsResponse
	err = json.NewDecoder(response.Body).Decode(&projects)
	if err != nil {
		return projectsResponse{}, err
	}
	return projects, nil
}

func (c *client) getIssues(organizationID, projectID string) (issuesResponse, error) {
	postData := issuesPostData{
		Filters: issueFilters{
			Severities: []string{
				"high", "medium", "low",
			},
		},
	}
	var reader bytes.Buffer
	err := json.NewEncoder(&reader).Encode(&postData)
	if err != nil {
		return issuesResponse{}, err
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/org/%s/project/%s/issues", c.baseURL, organizationID, projectID), &reader)
	if err != nil {
		return issuesResponse{}, err
	}
	response, err := c.do(req)
	if err != nil {
		return issuesResponse{}, err
	}
	var issues issuesResponse
	err = json.NewDecoder(response.Body).Decode(&issues)
	if err != nil {
		return issuesResponse{}, err
	}
	return issues, nil
}

func (c *client) do(req *http.Request) (*http.Response, error) {
	req.Header.Add("Authorization", fmt.Sprintf("token %s", c.token))
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Errorf("read body failed: %v", err)
			body = []byte("failed to read body")
		}
		requestDump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			log.Debugf("Failed to dump request for logging")
		} else {
			log.Debugf("Failed request dump: %s", requestDump)
		}
		return nil, fmt.Errorf("request not OK: %s: body: %s", response.Status, body)
	}
	return response, nil
}

type orgsResponse struct {
	Orgs []org `json:"orgs,omitempty"`
}

type org struct {
	ID    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
	Group *struct {
		Name string `json:"name,omitempty"`
		ID   string `json:"id,omitempty"`
	} `json:"group,omitempty"`
}

type projectsResponse struct {
	Org      projectOrg `json:"org,omitempty"`
	Projects []project  `json:"projects,omitempty"`
}

type projectOrg struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type project struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"id,omitempty"`
}

type issuesResponse struct {
	Issues issues `json:"issues,omitempty"`
}

type issues struct {
	Vulnerabilities []vulnerability `json:"vulnerabilities,omitempty"`
	Licenses        []license       `json:"licenses,omitempty"`
}

type vulnerability struct {
	ID       string `json:"id,omitempty"`
	Severity string `json:"severity,omitempty"`
	Title    string `json:"title,omitempty"`
	Ignored  bool   `json:"isIgnored"`
}

type license struct{}

type issuesPostData struct {
	Filters issueFilters `json:"filters,omitempty"`
}
type issueFilters struct {
	Severities []string `json:"severities,omitempty"`
	Types      []string `json:"types,omitempty"`
	Ignored    bool     `json:"ignored,omitempty"`
	Patched    bool     `json:"patched,omitempty"`
}
