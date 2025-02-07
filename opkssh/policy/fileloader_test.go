package policy_test

import (
	"errors"
	"os"
	"os/user"
	"path"
	"testing"

	"github.com/bastionzero/opk-ssh/policy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

type MockUserLookup struct {
	// User is returned on any call to Lookup() if Error is nil
	User *user.User
	// Error is returned on any call to Lookup() if non-nil
	Error error
}

var _ policy.UserLookup = &MockUserLookup{}

// Lookup implements policy.UserLookup
func (m *MockUserLookup) Lookup(username string) (*user.User, error) {
	if m.Error == nil {
		return m.User, nil
	} else {
		return nil, m.Error
	}
}

// MockFsOpenError embeds an afero.MemMapFs (implements afero.Fs) but allows for
// finer control on when an error should be returned on a specific filepath
type MockFsOpenError struct {
	afero.MemMapFs

	fileToErrorMap map[string]error
}

func NewMockFsOpenError() *MockFsOpenError {
	return &MockFsOpenError{fileToErrorMap: make(map[string]error)}
}

func (m *MockFsOpenError) Open(name string) (afero.File, error) {
	err, ok := m.fileToErrorMap[name]
	if ok {
		return nil, err
	}
	return m.MemMapFs.Open(name)
}

// ErrorOn makes Open(fileName) return err
func (m *MockFsOpenError) ErrorOn(fileName string, err error) {
	m.fileToErrorMap[fileName] = err
}

func NewTestPolicyFileLoader(fs afero.Fs, userLookup policy.UserLookup) *policy.FileLoader {
	return &policy.FileLoader{
		Fs:         fs,
		UserLookup: userLookup,
	}
}

var ValidUser *user.User = &user.User{HomeDir: "/home/foo", Username: "foo"}

func TestLoadUserPolicy_FailUserLookup(t *testing.T) {
	// Test that LoadUserPolicy returns an error when user lookup fails
	t.Parallel()

	fakeError := errors.New("fake error")
	mockUserLookup := &MockUserLookup{Error: fakeError}

	policyLoader := NewTestPolicyFileLoader(afero.NewMemMapFs(), mockUserLookup)
	policy, path, err := policyLoader.LoadUserPolicy("", false)

	require.ErrorIs(t, err, fakeError)
	require.Nil(t, policy, "should not return policy if error")
	require.Empty(t, path, "should not return path if error")
}

func TestLoadUserPolicy_NoUserHomeDir(t *testing.T) {
	// Test that LoadUserPolicy returns an error when the user does not have a
	// home directory
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: &user.User{}}

	policyLoader := NewTestPolicyFileLoader(afero.NewMemMapFs(), mockUserLookup)
	policy, path, err := policyLoader.LoadUserPolicy("", false)

	require.Error(t, err, "should not read policy if user does not have a home directory")
	require.Nil(t, policy, "should not return policy if error")
	require.Empty(t, path, "should not return path if error")
}

func TestLoadUserPolicy_ErrorYAML(t *testing.T) {
	// Test that LoadUserPolicy returns an error when the YAML is invalid
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}
	policyLoader := NewTestPolicyFileLoader(afero.NewMemMapFs(), mockUserLookup)
	mockFs := policyLoader.Fs
	// Create policy file at user policy path with invalid yaml
	afero.WriteFile(mockFs, path.Join(ValidUser.HomeDir, ".opk", "policy.yml"), []byte("{"), 0600)

	policy, path, err := policyLoader.LoadUserPolicy(ValidUser.Username, false)

	require.Error(t, err)
	require.Nil(t, policy, "should not return policy if error")
	require.Empty(t, path, "should not return path if error")
}

func TestLoadUserPolicy_Success(t *testing.T) {
	// Test that LoadUserPolicy returns the policy when there are no errors
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}
	policyLoader := NewTestPolicyFileLoader(afero.NewMemMapFs(), mockUserLookup)
	mockFs := policyLoader.Fs
	// Create policy file at path with valid yaml
	testPolicy := &policy.Policy{
		Users: []policy.User{
			{
				Email:      "alice@example.com",
				Principals: []string{"test"},
			},
		},
	}
	testPolicyYaml, err := testPolicy.ToYAML()
	require.NoError(t, err)
	expectedPath := path.Join(ValidUser.HomeDir, ".opk", "policy.yml")
	afero.WriteFile(mockFs, expectedPath, testPolicyYaml, 0600)

	gotPolicy, gotPath, err := policyLoader.LoadUserPolicy(ValidUser.Username, false)

	require.NoError(t, err)
	require.Equal(t, testPolicy, gotPolicy)
	require.Equal(t, expectedPath, gotPath)
}

func TestLoadUserPolicy_Success_SkipInvalidEntries(t *testing.T) {
	// Test that LoadUserPolicy returns the policy when there are no errors and
	// correctly skips invalid entries
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}
	policyLoader := NewTestPolicyFileLoader(afero.NewMemMapFs(), mockUserLookup)
	mockFs := policyLoader.Fs
	// Create policy file at path with valid yaml
	testPolicy := &policy.Policy{
		Users: []policy.User{
			{
				Email:      "alice@example.com",
				Principals: []string{"test"},
			},
			{
				Email:      "bob@example.com",
				Principals: []string{"test"},
			},
			{
				Email:      "charlie@example.com",
				Principals: []string{ValidUser.Username},
			},
			{
				Email:      "daniel@example.com",
				Principals: []string{ValidUser.Username, "test", "test2"},
			},
		},
	}
	// Expect only user statements that contain ValidUser.Username
	expectedPolicy := &policy.Policy{
		Users: []policy.User{
			{
				Email:      "charlie@example.com",
				Principals: []string{ValidUser.Username},
			},
			{
				Email:      "daniel@example.com",
				Principals: []string{ValidUser.Username},
			},
		},
	}
	testPolicyYaml, err := testPolicy.ToYAML()
	require.NoError(t, err)
	expectedPath := path.Join(ValidUser.HomeDir, ".opk", "policy.yml")
	afero.WriteFile(mockFs, expectedPath, testPolicyYaml, 0600)

	gotPolicy, gotPath, err := policyLoader.LoadUserPolicy(ValidUser.Username, true)

	require.NoError(t, err)
	require.Equal(t, expectedPolicy, gotPolicy)
	require.Equal(t, expectedPath, gotPath)
}

func TestLoadPolicyAtPath_FileMissing(t *testing.T) {
	// Test that LoadPolicyAtPath returns an error when the file cannot be
	// found at the specified path
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}

	policyLoader := NewTestPolicyFileLoader(afero.NewMemMapFs(), mockUserLookup)
	contents, err := policyLoader.LoadPolicyAtPath("/policy.yml")

	require.ErrorIs(t, err, os.ErrNotExist)
	require.Nil(t, contents, "should not return contents if error")
}

func TestLoadPolicyAtPath_BadPermissions(t *testing.T) {
	// Test that LoadPolicyAtPath returns an error when the file has invalid
	// permission bits
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}
	mockFs := NewMockFsOpenError()
	policyLoader := NewTestPolicyFileLoader(
		mockFs,
		mockUserLookup,
	)
	// Create empty policy with bad permissions
	afero.WriteFile(mockFs, policy.SystemDefaultPolicyPath, []byte{}, 0777)

	contents, err := policyLoader.LoadPolicyAtPath(policy.SystemDefaultPolicyPath)

	require.Error(t, err, "should fail if permissions are bad")
	require.Nil(t, contents, "should not return contents if error")
}

func TestLoadPolicyAtPath_ReadError(t *testing.T) {
	// Test that LoadPolicyAtPath returns an error when we fail to read the file
	// (but it exists)
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}
	mockFs := NewMockFsOpenError()
	policyLoader := NewTestPolicyFileLoader(
		mockFs,
		mockUserLookup,
	)
	// Create empty policy file with correct permissions
	afero.WriteFile(mockFs, policy.SystemDefaultPolicyPath, []byte{}, 0600)
	// Now make it so mock filesystem returns error when reading the file (must
	// do this after creating the SystemDefaultPolicyPath file above)
	fakeError := errors.New("fake error")
	mockFs.ErrorOn(policy.SystemDefaultPolicyPath, fakeError)

	contents, err := policyLoader.LoadPolicyAtPath(policy.SystemDefaultPolicyPath)

	require.ErrorIs(t, err, fakeError)
	require.Nil(t, contents, "should not return contents if error")
}

func TestLoadSystemDefaultPolicy_ErrorYAML(t *testing.T) {
	// Test that LoadSystemDefaultPolicy returns an error when the YAML is
	// invalid
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}
	policyLoader := NewTestPolicyFileLoader(afero.NewMemMapFs(), mockUserLookup)
	mockFs := policyLoader.Fs
	// Create policy file at default path with invalid yaml
	afero.WriteFile(mockFs, policy.SystemDefaultPolicyPath, []byte("{"), 0600)

	policy, err := policyLoader.LoadSystemDefaultPolicy()

	require.Error(t, err)
	require.Nil(t, policy, "should not return policy if error")
}

func TestLoadSystemDefaultPolicy_Success(t *testing.T) {
	// Test that LoadSystemDefaultPolicy returns the policy when there are no
	// errors
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}
	policyLoader := NewTestPolicyFileLoader(afero.NewMemMapFs(), mockUserLookup)
	mockFs := policyLoader.Fs
	// Create policy file at default path with valid yaml
	testPolicy := &policy.Policy{
		Users: []policy.User{
			{
				Email:      "alice@example.com",
				Principals: []string{"test"},
			},
		},
	}
	testPolicyYaml, err := testPolicy.ToYAML()
	require.NoError(t, err)
	afero.WriteFile(mockFs, policy.SystemDefaultPolicyPath, testPolicyYaml, 0600)

	gotPolicy, err := policyLoader.LoadSystemDefaultPolicy()

	require.NoError(t, err)
	require.Equal(t, testPolicy, gotPolicy)
}

func TestDump_Success(t *testing.T) {
	// Test that Dump writes the policy to the mock filesystem when there are no
	// errors
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}
	testPolicy := &policy.Policy{
		Users: []policy.User{
			{
				Email:      "alice@example.com",
				Principals: []string{"test"},
			},
		},
	}
	expectedContents, err := testPolicy.ToYAML()
	require.NoError(t, err)
	policyLoader := NewTestPolicyFileLoader(afero.NewMemMapFs(), mockUserLookup)
	mockFs := policyLoader.Fs

	err = policyLoader.Dump(testPolicy, policy.SystemDefaultPolicyPath)

	require.NoError(t, err)
	gotContents, err := afero.ReadFile(mockFs, policy.SystemDefaultPolicyPath)
	require.NoError(t, err)
	require.Equal(t, expectedContents, gotContents)
}
