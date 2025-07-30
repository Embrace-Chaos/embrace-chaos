package domain

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration is a wrapper around time.Duration with JSON marshaling support
type Duration time.Duration

// MarshalJSON implements json.Marshaler
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, time.Duration(d).String())), nil
}

// UnmarshalJSON implements json.Unmarshaler
func (d *Duration) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	duration, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(duration)
	return nil
}

// String returns the string representation
func (d Duration) String() string {
	return time.Duration(d).String()
}

// Seconds returns the duration as seconds
func (d Duration) Seconds() float64 {
	return time.Duration(d).Seconds()
}

// Minutes returns the duration as minutes
func (d Duration) Minutes() float64 {
	return time.Duration(d).Minutes()
}

// Hours returns the duration as hours
func (d Duration) Hours() float64 {
	return time.Duration(d).Hours()
}

// IsZero returns true if the duration is zero
func (d Duration) IsZero() bool {
	return time.Duration(d) == 0
}

// IsPositive returns true if the duration is positive
func (d Duration) IsPositive() bool {
	return time.Duration(d) > 0
}

// Percentage represents a percentage value (0-100)
type Percentage float64

// NewPercentage creates a new percentage with validation
func NewPercentage(value float64) (Percentage, error) {
	if value < 0 || value > 100 {
		return 0, NewValidationError("percentage must be between 0 and 100, got %.2f", value)
	}
	return Percentage(value), nil
}

// MustPercentage creates a new percentage, panicking on invalid values
func MustPercentage(value float64) Percentage {
	p, err := NewPercentage(value)
	if err != nil {
		panic(err)
	}
	return p
}

// MarshalJSON implements json.Marshaler
func (p Percentage) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%.2f", float64(p))), nil
}

// UnmarshalJSON implements json.Unmarshaler
func (p *Percentage) UnmarshalJSON(data []byte) error {
	value, err := strconv.ParseFloat(string(data), 64)
	if err != nil {
		return err
	}
	
	percentage, err := NewPercentage(value)
	if err != nil {
		return err
	}
	
	*p = percentage
	return nil
}

// String returns the string representation
func (p Percentage) String() string {
	return fmt.Sprintf("%.2f%%", float64(p))
}

// Float64 returns the percentage as a float64
func (p Percentage) Float64() float64 {
	return float64(p)
}

// Decimal returns the percentage as a decimal (0.0-1.0)
func (p Percentage) Decimal() float64 {
	return float64(p) / 100.0
}

// IsZero returns true if the percentage is zero
func (p Percentage) IsZero() bool {
	return p == 0
}

// IsMax returns true if the percentage is 100%
func (p Percentage) IsMax() bool {
	return p == 100
}

// Validate validates the percentage value
func (p Percentage) Validate() error {
	if p < 0 || p > 100 {
		return NewValidationError("percentage must be between 0 and 100, got %.2f", float64(p))
	}
	return nil
}

// Email represents an email address with validation
type Email string

// NewEmail creates a new email with validation
func NewEmail(email string) (Email, error) {
	if email == "" {
		return "", NewValidationError("email cannot be empty")
	}
	
	// Basic email validation
	if !strings.Contains(email, "@") {
		return "", NewValidationError("invalid email format: %s", email)
	}
	
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "", NewValidationError("invalid email format: %s", email)
	}
	
	if parts[0] == "" || parts[1] == "" {
		return "", NewValidationError("invalid email format: %s", email)
	}
	
	return Email(email), nil
}

// String returns the string representation
func (e Email) String() string {
	return string(e)
}

// Domain returns the domain part of the email
func (e Email) Domain() string {
	parts := strings.Split(string(e), "@")
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// LocalPart returns the local part of the email
func (e Email) LocalPart() string {
	parts := strings.Split(string(e), "@")
	if len(parts) == 2 {
		return parts[0]
	}
	return ""
}

// Validate validates the email
func (e Email) Validate() error {
	_, err := NewEmail(string(e))
	return err
}

// Priority represents a priority level
type Priority int

const (
	PriorityLow Priority = iota
	PriorityMedium
	PriorityHigh
	PriorityCritical
)

var priorityNames = map[Priority]string{
	PriorityLow:      "low",
	PriorityMedium:   "medium",
	PriorityHigh:     "high",
	PriorityCritical: "critical",
}

var priorityValues = map[string]Priority{
	"low":      PriorityLow,
	"medium":   PriorityMedium,
	"high":     PriorityHigh,
	"critical": PriorityCritical,
}

// String returns the string representation
func (p Priority) String() string {
	if name, exists := priorityNames[p]; exists {
		return name
	}
	return "unknown"
}

// MarshalJSON implements json.Marshaler
func (p Priority) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, p.String())), nil
}

// UnmarshalJSON implements json.Unmarshaler
func (p *Priority) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if priority, exists := priorityValues[s]; exists {
		*p = priority
		return nil
	}
	return NewValidationError("invalid priority: %s", s)
}

// IsHigherThan returns true if this priority is higher than the other
func (p Priority) IsHigherThan(other Priority) bool {
	return p > other
}

// IsLowerThan returns true if this priority is lower than the other
func (p Priority) IsLowerThan(other Priority) bool {
	return p < other
}

// Severity represents a severity level
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityError
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityInfo:     "info",
	SeverityWarning:  "warning",
	SeverityError:    "error",
	SeverityCritical: "critical",
}

var severityValues = map[string]Severity{
	"info":     SeverityInfo,
	"warning":  SeverityWarning,
	"error":    SeverityError,
	"critical": SeverityCritical,
}

// String returns the string representation
func (s Severity) String() string {
	if name, exists := severityNames[s]; exists {
		return name
	}
	return "unknown"
}

// MarshalJSON implements json.Marshaler
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, s.String())), nil
}

// UnmarshalJSON implements json.Unmarshaler
func (s *Severity) UnmarshalJSON(data []byte) error {
	str := strings.Trim(string(data), `"`)
	if severity, exists := severityValues[str]; exists {
		*s = severity
		return nil
	}
	return NewValidationError("invalid severity: %s", str)
}

// IsHigherThan returns true if this severity is higher than the other
func (s Severity) IsHigherThan(other Severity) bool {
	return s > other
}

// IsLowerThan returns true if this severity is lower than the other
func (s Severity) IsLowerThan(other Severity) bool {
	return s < other
}

// Version represents a semantic version
type Version struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
	Patch int `json:"patch"`
	Pre   string `json:"pre,omitempty"`
	Build string `json:"build,omitempty"`
}

// NewVersion creates a new version
func NewVersion(major, minor, patch int) Version {
	return Version{
		Major: major,
		Minor: minor,
		Patch: patch,
	}
}

// ParseVersion parses a version string (e.g., "1.2.3-alpha+build")
func ParseVersion(s string) (Version, error) {
	var v Version
	
	// Remove build metadata
	parts := strings.Split(s, "+")
	versionPart := parts[0]
	if len(parts) > 1 {
		v.Build = parts[1]
	}
	
	// Handle pre-release
	parts = strings.Split(versionPart, "-")
	versionPart = parts[0]
	if len(parts) > 1 {
		v.Pre = parts[1]
	}
	
	// Parse major.minor.patch
	parts = strings.Split(versionPart, ".")
	if len(parts) != 3 {
		return v, NewValidationError("invalid version format: %s", s)
	}
	
	var err error
	if v.Major, err = strconv.Atoi(parts[0]); err != nil {
		return v, NewValidationError("invalid major version: %s", parts[0])
	}
	
	if v.Minor, err = strconv.Atoi(parts[1]); err != nil {
		return v, NewValidationError("invalid minor version: %s", parts[1])
	}
	
	if v.Patch, err = strconv.Atoi(parts[2]); err != nil {
		return v, NewValidationError("invalid patch version: %s", parts[2])
	}
	
	return v, nil
}

// String returns the string representation
func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	if v.Build != "" {
		s += "+" + v.Build
	}
	return s
}

// MarshalJSON implements json.Marshaler
func (v Version) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, v.String())), nil
}

// UnmarshalJSON implements json.Unmarshaler
func (v *Version) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	version, err := ParseVersion(s)
	if err != nil {
		return err
	}
	*v = version
	return nil
}

// Compare compares two versions (-1, 0, 1)
func (v Version) Compare(other Version) int {
	if v.Major != other.Major {
		if v.Major > other.Major {
			return 1
		}
		return -1
	}
	
	if v.Minor != other.Minor {
		if v.Minor > other.Minor {
			return 1
		}
		return -1
	}
	
	if v.Patch != other.Patch {
		if v.Patch > other.Patch {
			return 1
		}
		return -1
	}
	
	// Pre-release comparison
	if v.Pre == "" && other.Pre != "" {
		return 1 // No pre-release is higher than pre-release
	}
	if v.Pre != "" && other.Pre == "" {
		return -1
	}
	if v.Pre != other.Pre {
		if v.Pre > other.Pre {
			return 1
		}
		return -1
	}
	
	return 0
}

// IsGreaterThan returns true if this version is greater than the other
func (v Version) IsGreaterThan(other Version) bool {
	return v.Compare(other) > 0
}

// IsLessThan returns true if this version is less than the other
func (v Version) IsLessThan(other Version) bool {
	return v.Compare(other) < 0
}

// Equals returns true if the versions are equal
func (v Version) Equals(other Version) bool {
	return v.Compare(other) == 0
}

// IsPreRelease returns true if this is a pre-release version
func (v Version) IsPreRelease() bool {
	return v.Pre != ""
}

// Tags represents a collection of tags with validation
type Tags []string

// NewTags creates a new tags collection
func NewTags(tags ...string) Tags {
	return Tags(tags)
}

// Add adds a tag if it doesn't already exist
func (t *Tags) Add(tag string) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return
	}
	
	// Check if already exists
	for _, existing := range *t {
		if existing == tag {
			return
		}
	}
	
	*t = append(*t, tag)
}

// Remove removes a tag
func (t *Tags) Remove(tag string) {
	for i, existing := range *t {
		if existing == tag {
			*t = append((*t)[:i], (*t)[i+1:]...)
			return
		}
	}
}

// Contains checks if a tag exists
func (t Tags) Contains(tag string) bool {
	for _, existing := range t {
		if existing == tag {
			return true
		}
	}
	return false
}

// IsEmpty returns true if there are no tags
func (t Tags) IsEmpty() bool {
	return len(t) == 0
}

// Count returns the number of tags
func (t Tags) Count() int {
	return len(t)
}

// String returns a comma-separated string representation
func (t Tags) String() string {
	return strings.Join(t, ", ")
}

// Validate validates all tags
func (t Tags) Validate() error {
	for i, tag := range t {
		if strings.TrimSpace(tag) == "" {
			return NewValidationError("tag at index %d cannot be empty", i)
		}
		if len(tag) > 50 {
			return NewValidationError("tag at index %d cannot exceed 50 characters", i)
		}
	}
	return nil
}