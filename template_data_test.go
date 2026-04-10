package websession_test

import (
	"testing"

	"github.com/borghives/websession"
)

// TestCreateTemplateData tests the CreateTemplateData function
func TestCreateTemplateData(t *testing.T) {
	id := "testID"
	rid := "testRootID"
	// Create a mock session
	// Note: websession.Session is a struct. We need to provide values for fields
	// that are accessed in CreateTemplateData or by entanglement.CreateEntanglement.
	// Looking at CreateTemplateData, it accesses session.UserName.
	// entanglement.CreateEntanglement might access more. For now, just UserName.
	mockSession := &websession.Session{
		UserName: "testUser",
		// Fill other fields if necessary for entanglement.CreateEntanglement
	}

	data := websession.CreateTemplateData(id, rid, mockSession)

	if data.ID != id {
		t.Errorf("Expected ID %s, got %s", id, data.ID)
	}
	if data.RootId != rid {
		t.Errorf("Expected RootId %s, got %s", rid, data.RootId)
	}
	if data.Username != mockSession.UserName {
		t.Errorf("Expected Username %s, got %s", mockSession.UserName, data.Username)
	}
}

// TestMakeTemplateFunc tests the MakeTemplateFunc method
func TestMakeTemplateFunc(t *testing.T) {
	// Create a TemplateData instance to call the method on
	td := websession.TemplateData{}
	funcMap := td.MakeTemplateFunc()

	if funcMap == nil {
		t.Fatal("MakeTemplateFunc returned nil, expected a template.FuncMap")
	}

	// Check for the existence of "gettopic" function
	gettopicFunc, ok := funcMap["gettopic"]
	if !ok {
		t.Error("Expected FuncMap to contain 'gettopic' function, but it was not found")
	}

	// Test the functionality of "gettopic"
	if gtFunc, okTyped := gettopicFunc.(func() string); okTyped {
		result := gtFunc()
		expected := "hello"
		if result != expected {
			t.Errorf("'gettopic' function returned %s, expected %s", result, expected)
		}
	} else {
		t.Errorf("'gettopic' function is not of type func() string")
	}

	// Verify no other functions are present if that's the expectation
	if len(funcMap) != 1 {
		t.Errorf("Expected FuncMap to contain 1 function, but found %d", len(funcMap))
		// For debugging, list the functions found:
		keys := make([]string, 0, len(funcMap))
		for k := range funcMap {
			keys = append(keys, k)
		}
		t.Logf("Functions found in FuncMap: %v", keys)
	}
}
