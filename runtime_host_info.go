package websession

import (
	"log"
	"os"
	"strings"
	"sync"

	"github.com/borghives/kosmos-go"
)

type RutimeHostInfo struct {
	kosmos.BaseModel `bson:",inline" kosmos:"hostinfo"`
	BuildId          string   `bson:"build_id"`
	ImageId          string   `bson:"image_id"`
	AppName          string   `bson:"app_name"`
	AppCommand       string   `bson:"app_command"`
	EnvVars          []string `bson:"env_vars"`
}

func getNonSecretEnvVars() []string {
	envVars := []string{}
	for _, env := range os.Environ() {
		//exclude secrets
		if !strings.HasPrefix(env, "CSRF_LATEST") &&
			!strings.HasPrefix(env, "SESSION_LATEST") &&
			!strings.HasPrefix(env, "SECRET_") &&
			!strings.Contains(env, "SECRET") {
			envVars = append(envVars, env)
		}
	}
	return envVars
}

var (
	hostinfo RutimeHostInfo
	once     sync.Once
)

func GetHostInfo() RutimeHostInfo {
	once.Do(func() {
		hostinfo = getHostInfo()
	})
	return hostinfo
}

func getHostInfo() RutimeHostInfo {
	retval := RutimeHostInfo{
		BuildId:    os.Getenv("BUILD_ID"),
		ImageId:    os.Getenv("IMAGE_DIGEST"),
		AppName:    os.Getenv("APP_NAME"),
		AppCommand: strings.Join(os.Args, " "),
		EnvVars:    getNonSecretEnvVars(),
	}
	retval.CollapseID()
	return retval
}

func GetAllowedHosts() map[string]bool {
	// Determine allowed hosts for HTTP service.
	var allowedHosts = map[string]bool{}
	envAllowHosts := os.Getenv("ALLOW_HOSTS")
	for host := range strings.SplitSeq(envAllowHosts, " ") {
		allowedHosts[host] = true
		log.Printf("Has allow host: %s", host)
	}
	return allowedHosts
}
