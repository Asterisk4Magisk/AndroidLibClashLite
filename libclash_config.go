package libclash

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"sync"

	"cfa/native/config"
)

// Completion receives an empty errorText on success, otherwise an error message.
// Kotlin coroutine objects stay in the app; implement this interface to complete them.
type Completion interface{ Complete(errorText string) }

type FetchCallback interface {
	Report(statusJSON string)
	Complete(errorText string)
}

var fetchTasks = struct {
	sync.Mutex
	values map[int64]context.CancelFunc
}{values: make(map[int64]context.CancelFunc)}

// FetchAndValid starts an asynchronous fetch. taskID must be unique until Complete.
func FetchAndValid(callback FetchCallback, taskID int64, path, url, optionsJSON string) error {
	if callback == nil {
		return errors.New("fetch callback is required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	fetchTasks.Lock()
	if _, exists := fetchTasks.values[taskID]; exists {
		fetchTasks.Unlock()
		cancel()
		return errors.New("fetch task ID is already active")
	}
	fetchTasks.values[taskID] = cancel
	fetchTasks.Unlock()
	go func() {
		defer runtime.GC()
		defer cancel()
		var options config.FetchOptions
		err := json.Unmarshal([]byte(optionsJSON), &options)
		if err == nil {
			err = config.FetchAndValid(ctx, path, url, options, callback.Report)
		}
		fetchTasks.Lock()
		delete(fetchTasks.values, taskID)
		fetchTasks.Unlock()
		callback.Complete(errorText(err))
	}()
	return nil
}

func CancelFetch(taskID int64) {
	fetchTasks.Lock()
	cancel := fetchTasks.values[taskID]
	fetchTasks.Unlock()
	if cancel != nil {
		cancel()
	}
}

func Load(callback Completion, path string) error {
	if callback == nil {
		return errors.New("completion callback is required")
	}
	go func() { callback.Complete(errorText(config.Load(path))); runtime.GC() }()
	return nil
}

func LoadFromBytes(callback Completion, path string, content []byte) error {
	if callback == nil {
		return errors.New("completion callback is required")
	}
	// Do not retain the Java byte-array storage after the binding call returns.
	data := append([]byte(nil), content...)
	go func() { callback.Complete(errorText(config.LoadBytes(path, data))); runtime.GC() }()
	return nil
}

func ReadOverride(slot int32) string { return config.ReadOverride(config.OverrideSlot(slot)) }
func WriteOverride(slot int32, content string) {
	config.WriteOverride(config.OverrideSlot(slot), content)
}
func ClearOverride(slot int32) { config.ClearOverride(config.OverrideSlot(slot)) }

// SetAgeSecretKey clears the global keys when key is empty.
func SetAgeSecretKey(key string) {
	if key == "" {
		config.SetGlobalSecretKeys()
	} else {
		config.SetGlobalSecretKeys(key)
	}
}

// DecryptAge returns plaintext; failures become Java exceptions.
func DecryptAge(content, secretKeys string) (string, error) {
	var keys []string
	if secretKeys != "" {
		keys = append(keys, secretKeys)
	}
	result, err := config.DecryptBytes([]byte(content), keys...)
	return string(result), err
}

func VeritySecretKeys(keys string) bool { return config.VeritySecretKeys(keys) == nil }
func errorText(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

func marshalJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func errorResponse(err error) string { return marshalJSON(map[string]string{"error": err.Error()}) }
