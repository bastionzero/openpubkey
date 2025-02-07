package policy

import (
	"fmt"
	"io/fs"
	"os/user"
	"path"

	"github.com/spf13/afero"
	"golang.org/x/exp/slices"
)

// SystemDefaultPolicyPath is the default filepath where opk-ssh policy is
// defined
const SystemDefaultPolicyPath = "/etc/opk/policy.yml"

// ModeOnlyOwner is the expected permission bits that should be set for opk-ssh
// policy files. This mode means that only the owner of the file can read/write
const ModeOnlyOwner = fs.FileMode(0600)

// UserLookup defines the minimal interface to lookup users on the current
// system
type UserLookup interface {
	Lookup(username string) (*user.User, error)
}

// OsUserLookup implements the UserLookup interface by invoking the os/user
// library
type OsUserLookup struct{}

func NewOsUserLookup() UserLookup {
	return &OsUserLookup{}
}
func (OsUserLookup) Lookup(username string) (*user.User, error) { return user.Lookup(username) }

// FileLoader contains methods to read/write the opk-ssh policy file from/to an
// arbitrary filesystem. All methods that read policy from the filesystem fail
// and return an error immediately if the permission bits are invalid.
type FileLoader struct {
	Fs         afero.Fs
	UserLookup UserLookup
}

// NewFileLoader returns an opk-ssh policy loader that uses the os library to
// read/write policy from/to the filesystem.
func NewFileLoader() *FileLoader {
	return &FileLoader{
		Fs:         afero.NewOsFs(),
		UserLookup: NewOsUserLookup(),
	}
}

// LoadPolicyAtPath validates that the policy file at path exists, can be read
// by the current process, and has the correct permission bits set. Parses the
// contents and returns a policy.Policy if file permissions are valid and
// reading is successful; otherwise returns an error.
func (l *FileLoader) LoadPolicyAtPath(path string) (*Policy, error) {
	// Get file info and check if file exists
	info, err := l.Fs.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to describe the file at path: %w", err)
	}

	// Validate that file has correct permission bits set
	err = l.validatePermissions(info)
	if err != nil {
		return nil, fmt.Errorf("policy file has insecure permissions: %w", err)
	}

	// Read file contents
	afs := &afero.Afero{Fs: l.Fs}
	content, err := afs.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Convert from YAML
	policy, err := FromYAML(content)
	if err != nil {
		return nil, err
	}

	return policy, nil
}

// LoadSystemDefaultPolicy reads the opk-ssh policy at SystemDefaultPolicyPath.
// An error is returned if the file cannot be read or if the permissions bits
// are not correct.
func (l *FileLoader) LoadSystemDefaultPolicy() (*Policy, error) {
	policy, err := l.LoadPolicyAtPath(SystemDefaultPolicyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read system default policy file %s: %w", SystemDefaultPolicyPath, err)
	}

	return policy, nil
}

// LoadUserPolicy reads the user's opk-ssh policy at ~/.opk/policy.yml (where ~
// maps to username's home directory) and returns the filepath read. An error is
// returned if the file cannot be read, if the permission bits are not correct,
// or if there is no user with username or has no home directory.
//
// If skipInvalidEntries is true, then invalid user entries are skipped and not
// included in the returned policy. A user policy's entry is considered valid if
// it gives username access. The returned policy is stripped of invalid entries.
func (l *FileLoader) LoadUserPolicy(username string, skipInvalidEntries bool) (*Policy, string, error) {
	user, err := l.UserLookup.Lookup(username)
	if err != nil {
		return nil, "", fmt.Errorf("failed to lookup username %s: %w", username, err)
	}
	userHomeDirectory := user.HomeDir
	if userHomeDirectory == "" {
		return nil, "", fmt.Errorf("user %s does not have a home directory", username)
	}

	policyFilePath := path.Join(userHomeDirectory, ".opk", "policy.yml")
	policy, err := l.LoadPolicyAtPath(policyFilePath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read user policy file %s: %w", policyFilePath, err)
	}

	if skipInvalidEntries {
		// Build valid user policy. Ignore user entries that give access to a
		// principal not equal to the username where the policy file was read
		// from.
		validUserPolicy := new(Policy)
		for _, user := range policy.Users {
			if slices.Contains(user.Principals, username) {
				// Build clean entry that only gives access to username
				validUserPolicy.Users = append(validUserPolicy.Users, User{
					Email:      user.Email,
					Principals: []string{username},
				})
			}
		}

		return validUserPolicy, policyFilePath, nil
	} else {
		// Just return what we read
		return policy, policyFilePath, nil
	}
}

func (l *FileLoader) validatePermissions(fileInfo fs.FileInfo) error {
	mode := fileInfo.Mode()

	// only the owner of this file should be able to write to it
	if mode.Perm() != ModeOnlyOwner {
		return fmt.Errorf("expected (0600), got (%o)", mode.Perm())
	}

	return nil
}

// Dump encodes the policy into YAML and writes the contents to the filepath
// path
func (l *FileLoader) Dump(policy *Policy, path string) error {
	yamlBytes, err := policy.ToYAML()
	if err != nil {
		return err
	}

	// Write to disk
	if err := afero.WriteFile(l.Fs, path, yamlBytes, ModeOnlyOwner); err != nil {
		return fmt.Errorf("failed to write to policy file %s: %w", path, err)
	}

	return nil
}
