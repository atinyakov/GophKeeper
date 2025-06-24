// Package config provides functionality for managing configuration options
// for the application using command-line flags and environment variables.
package config

import (
	"encoding/json"
	"flag"
	"log"
	"os"
)

// Options holds the configuration values for the application.
type Options struct {
	// Port defines the server's listening address (ip:port).
	Port string

	// DatabaseDSN holds the database connection string for the application.
	DatabaseDSN string

	// Config is the path to the Config file.
	Config string
}

// options holds the current configuration values.
var options = &Options{}

// init initializes command-line flags and sets default values.
func init() {
	flag.StringVar(&options.Port, "a", "localhost:8080", "run on ip:port server")
	flag.StringVar(&options.DatabaseDSN, "d", "", "db address")
	flag.StringVar(&options.Config, "config", "config.json", "path to config file")
	flag.StringVar(&options.Config, "c", "config.json", "path to config file (shorthand)")
}

// Parse parses the command-line flags and environment variables to set
// configuration values. It returns a pointer to the Options struct containing
// the parsed configuration values.
func Parse() *Options {
	flag.Parse()

	// Override flags with environment variables if set
	if configPath := os.Getenv("CONFIG"); configPath != "" {
		options.Config = configPath
	}

	if options.Config != "" {
		if _, err := os.Stat(options.Config); err == nil {
			data, err := os.ReadFile(options.Config)
			if err != nil {
				log.Fatalf("error while reading config file: %v", err)
			}
			if err := json.Unmarshal(data, options); err != nil {
				log.Fatalf("error while parsing config file: %v", err)
			}
		}
	}

	if serverAddress := os.Getenv("SERVER_ADDRESS"); serverAddress != "" {
		options.Port = serverAddress
	}

	return options
}
