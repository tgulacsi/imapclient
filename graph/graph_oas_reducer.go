//go:build never

// Copyright Tamás Gulácsi.
//
// SPDX-License-Identifier: GPL-3.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultURL = "https://aka.ms/graph/v1.0/openapi.yaml"

var httpMethods = map[string]bool{
	"get":     true,
	"put":     true,
	"post":    true,
	"delete":  true,
	"options": true,
	"head":    true,
	"patch":   true,
	"trace":   true,
}

type stats struct {
	pathsIn       int
	pathsOut      int
	opsOut        int
	componentsIn  int
	componentsOut int
}

type reducer struct {
	doc          map[string]any
	components   map[string]any
	keep         map[string]map[string]bool
	usedSecurity map[string]bool
	warnings     []string
}

func main() {
	if err := Main(); err != nil {
		log.Fatal(err)
	}
}

func Main() error {
	var inPath, outPath, srcURL string
	var quiet bool

	flag.StringVar(&inPath, "in", "openapi.yaml", "input OpenAPI YAML file; when empty, -url is downloaded")
	flag.StringVar(&outPath, "out", "openapi.slim.yaml", "output slim OpenAPI YAML file")
	flag.StringVar(&srcURL, "url", "", "source OpenAPI YAML URL used when -in is empty")
	flag.BoolVar(&quiet, "quiet", false, "suppress summary on stderr")
	flag.Parse()

	if inPath != "" {
		if _, err := os.Stat(inPath); err != nil {
			return err
		}
	} else if srcURL == "" {
		srcURL = defaultURL
	}
	b, err := readInput(inPath, srcURL)
	if err != nil {
		return err
	}

	var raw map[string]any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("parse YAML: %w", err)
	}

	doc, ok := normalize(raw).(map[string]any)
	if !ok {
		return errors.New("expected top-level YAML mapping")
	}

	out, s, warnings, err := reduce(doc, true)
	if err != nil {
		return err
	}

	outBytes, err := yaml.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal reduced YAML: %w", err)
	}

	if err := os.WriteFile(outPath, outBytes, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "wrote %s\n", outPath)
		fmt.Fprintf(os.Stderr, "paths: %d -> %d; operations kept: %d; components: %d -> %d\n", s.pathsIn, s.pathsOut, s.opsOut, s.componentsIn, s.componentsOut)
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "warning: %s\n", w)
		}
	}
	return nil
}

func readInput(inPath, srcURL string) ([]byte, error) {
	if inPath != "" {
		return os.ReadFile(inPath)
	}

	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Get(srcURL)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", srcURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("download %s: HTTP %s", srcURL, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func reduce(doc map[string]any, includeUsersList bool) (map[string]any, stats, []string, error) {
	paths := asMap(doc["paths"])
	if paths == nil {
		return nil, stats{}, nil, errors.New("input has no paths object")
	}

	components := asMap(doc["components"])
	if components == nil {
		components = map[string]any{}
	}

	r := &reducer{
		doc:          doc,
		components:   components,
		keep:         map[string]map[string]bool{},
		usedSecurity: map[string]bool{},
	}

	outPaths := map[string]any{}
	usedTags := map[string]bool{}
	var opCount int

	keys := slices.Sorted(maps.Keys(paths))
	for _, p := range keys {
		pathItem := asMap(paths[p])
		if pathItem == nil {
			continue
		}

		filtered, keptOps := filterPathItem(p, pathItem, includeUsersList)
		if keptOps == 0 {
			continue
		}

		outPaths[p] = filtered
		opCount += keptOps
		collectTags(filtered, usedTags)
		r.walk(filtered)
	}

	if len(outPaths) == 0 {
		return nil, stats{}, nil, errors.New("path filter matched no paths; check the source spec path templates")
	}

	// Root security applies to operations without an operation-level security field.
	if sec, ok := doc["security"]; ok {
		r.collectSecurity(sec)
	}

	out := map[string]any{}
	for _, k := range []string{"openapi", "swagger", "info", "jsonSchemaDialect", "servers", "security", "externalDocs"} {
		if v, ok := doc[k]; ok {
			out[k] = v
		}
	}
	for k, v := range doc {
		if strings.HasPrefix(k, "x-") {
			out[k] = v
		}
	}

	if tags := filterTopLevelTags(doc["tags"], usedTags); len(tags) > 0 {
		out["tags"] = tags
	}

	out["paths"] = outPaths
	outComponents := r.buildComponents()
	if len(outComponents) > 0 {
		out["components"] = outComponents
	}

	s := stats{
		pathsIn:       len(paths),
		pathsOut:      len(outPaths),
		opsOut:        opCount,
		componentsIn:  countComponents(components),
		componentsOut: countComponents(outComponents),
	}
	return out, s, r.warnings, nil
}

func filterPathItem(path string, item map[string]any, includeUsersList bool) (map[string]any, int) {
	mail := isMailPath(path)
	usersList := includeUsersList && isUsersListPath(path)
	if !mail && !usersList {
		return nil, 0
	}

	out := map[string]any{}
	keptOps := 0
	for _, k := range slices.Sorted(maps.Keys(item)) {
		v := item[k]
		lk := strings.ToLower(k)
		if httpMethods[lk] {
			if mail || (usersList && lk == "get") {
				out[k] = v
				keptOps++
			}
			continue
		}

		// Preserve Path Item metadata and shared path-level parameters.
		out[k] = v
	}

	if keptOps == 0 {
		return nil, 0
	}
	return out, keptOps
}

func isMailPath(path string) bool {
	if hasPathPrefix(path, "/me/mailFolders") || hasPathPrefix(path, "/me/messages") {
		return true
	}

	parts := splitPath(path)
	return len(parts) >= 3 && parts[0] == "users" && isTemplate(parts[1]) && (parts[2] == "mailFolders" || parts[2] == "messages")
}

func isUsersListPath(path string) bool {
	if path == "/users" {
		return true
	}
	parts := splitPath(path)
	return len(parts) == 2 && parts[0] == "users" && isTemplate(parts[1])
}

func hasPathPrefix(path, base string) bool {
	return path == base || strings.HasPrefix(path, base+"/")
}

func splitPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func isTemplate(s string) bool {
	return strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")
}

func (r *reducer) walk(v any) {
	switch x := v.(type) {
	case map[string]any:
		if ref, ok := x["$ref"].(string); ok {
			r.addRef(ref)
		}
		if sec, ok := x["security"]; ok {
			r.collectSecurity(sec)
		}
		for _, vv := range x {
			r.walk(vv)
		}
	case []any:
		for _, vv := range x {
			r.walk(vv)
		}
	}
}

func (r *reducer) addRef(ref string) {
	section, name, ok := parseComponentRef(ref)
	if !ok {
		return
	}
	if r.keep[section] == nil {
		r.keep[section] = map[string]bool{}
	}
	if r.keep[section][name] {
		return
	}

	r.keep[section][name] = true
	sectionMap := asMap(r.components[section])
	if sectionMap == nil {
		r.warnings = append(r.warnings, fmt.Sprintf("missing components.%s for ref %s", section, ref))
		return
	}
	item, ok := sectionMap[name]
	if !ok {
		r.warnings = append(r.warnings, fmt.Sprintf("missing components.%s[%q] for ref %s", section, name, ref))
		return
	}
	r.walk(item)
}

func parseComponentRef(ref string) (section, name string, ok bool) {
	const prefix = "#/components/"
	if !strings.HasPrefix(ref, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(ref, prefix)
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	// Keep the owning component even if a ref points at a nested JSON pointer.
	return decodeJSONPointerToken(parts[0]), decodeJSONPointerToken(parts[1]), true
}

func decodeJSONPointerToken(s string) string {
	// JSON Pointer escape order matters: ~1 first, then ~0.
	return strings.ReplaceAll(strings.ReplaceAll(s, "~1", "/"), "~0", "~")
}

func (r *reducer) collectSecurity(v any) {
	arr, ok := v.([]any)
	if !ok {
		return
	}
	for _, req := range arr {
		m := asMap(req)
		for name := range m {
			r.usedSecurity[name] = true
		}
	}
}

func (r *reducer) buildComponents() map[string]any {
	out := map[string]any{}

	sections := slices.Sorted(maps.Keys(r.keep))
	for _, section := range sections {
		origSection := asMap(r.components[section])
		if origSection == nil {
			continue
		}
		sectionOut := map[string]any{}
		names := slices.Sorted(maps.Keys(r.keep[section]))
		for _, name := range names {
			if item, ok := origSection[name]; ok {
				sectionOut[name] = item
			}
		}
		if len(sectionOut) > 0 {
			out[section] = sectionOut
		}
	}

	if len(r.usedSecurity) > 0 {
		origSchemes := asMap(r.components["securitySchemes"])
		if origSchemes == nil {
			r.warnings = append(r.warnings, "security is used but components.securitySchemes is missing")
			return out
		}

		securityOut := asMap(out["securitySchemes"])
		if securityOut == nil {
			securityOut = map[string]any{}
		}
		for _, name := range slices.Sorted(maps.Keys(r.usedSecurity)) {
			if scheme, ok := origSchemes[name]; ok {
				securityOut[name] = scheme
			} else {
				r.warnings = append(r.warnings, fmt.Sprintf("security scheme %q is used but missing from components.securitySchemes", name))
			}
		}
		if len(securityOut) > 0 {
			out["securitySchemes"] = securityOut
		}
	}

	return out
}

func collectTags(v any, used map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		if tags, ok := x["tags"].([]any); ok {
			for _, t := range tags {
				if s, ok := t.(string); ok {
					used[s] = true
				}
			}
		}
		for _, vv := range x {
			collectTags(vv, used)
		}
	case []any:
		for _, vv := range x {
			collectTags(vv, used)
		}
	}
}

func filterTopLevelTags(v any, used map[string]bool) []any {
	tags, ok := v.([]any)
	if !ok || len(used) == 0 {
		return nil
	}
	out := make([]any, 0, len(tags))
	for _, t := range tags {
		m := asMap(t)
		name, _ := m["name"].(string)
		if name != "" && used[name] {
			out = append(out, t)
		}
	}
	return out
}

func countComponents(components map[string]any) int {
	var n int
	for _, section := range components {
		if m := asMap(section); m != nil {
			n += len(m)
		}
	}
	return n
}

func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, v := range x {
			m[k] = normalize(v)
		}
		return m
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, v := range x {
			m[fmt.Sprint(k)] = normalize(v)
		}
		return m
	case []any:
		for i := range x {
			x[i] = normalize(x[i])
		}
		return x
	default:
		return x
	}
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
