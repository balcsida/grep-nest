package httpapi

import (
	"os"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOpenAPIAdminJobsPaginationContract(t *testing.T) {
	data, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}

	var document struct {
		Paths map[string]struct {
			Get struct {
				Parameters []struct {
					Name     string `yaml:"name"`
					In       string `yaml:"in"`
					Required *bool  `yaml:"required"`
					Schema   struct {
						Type      string `yaml:"type"`
						MinLength int    `yaml:"minLength"`
					} `yaml:"schema"`
				} `yaml:"parameters"`
			} `yaml:"get"`
		} `yaml:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required   []string `yaml:"required"`
				Properties map[string]struct {
					Type      string `yaml:"type"`
					MinLength int    `yaml:"minLength"`
					MaxItems  int    `yaml:"maxItems"`
				} `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}

	parameters := document.Paths["/v1/admin/jobs"].Get.Parameters
	if len(parameters) != 1 || parameters[0].Name != "cursor" || parameters[0].In != "query" || parameters[0].Required == nil || *parameters[0].Required || parameters[0].Schema.Type != "string" || parameters[0].Schema.MinLength != 1 {
		t.Fatalf("admin jobs cursor parameter = %#v, want optional non-empty query string", parameters)
	}

	jobs := document.Components.Schemas["AdminJobList"]
	if jobs.Properties["jobs"].MaxItems != 25 {
		t.Errorf("AdminJobList.jobs.maxItems = %d, want 25", jobs.Properties["jobs"].MaxItems)
	}
	nextCursor := jobs.Properties["next_cursor"]
	if nextCursor.Type != "string" || nextCursor.MinLength != 1 || slices.Contains(jobs.Required, "next_cursor") {
		t.Errorf("AdminJobList.next_cursor = %#v with required %v, want optional non-empty string", nextCursor, jobs.Required)
	}
}
