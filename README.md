# sigma-esf
Run Sigma detection rules on logs from the new MacOS Endpoint Security Framework.

This is a super simple CLI that ties together:
* [ProcessMonitor](https://github.com/objective-see/ProcessMonitor) and [FileMonitor](https://github.com/objective-see/FileMonitor) from Patrick Wardle to do the Endpoint Security Framework subscribing
* [sigma-go](https://github.com/bradleyjkemp/sigma-go) to take the stream of Endpoint Security events and match them against Sigma rules.

## Installation

1. Install ProcessMonitor and FileMonitor from https://objective-see.com/products/utilities.html
1. ⚠️ Make sure you follow the (Process|File)Monitor prerequisites so that Endpoint Security Framework works properly:
    * The terminal app you're using to run `sigma-esf` needs to have "Full Disk Access" granted.
    * You need to be running `sigma-esf` as root.
1. Install `sigma-esf` using either:
    * `go install github.com/bradleyjkemp/sigma-esf`
    * `brew install bradleyjkemp/formulae/sigma-esf`

## Usage
The most basic usage of `sigma-esf` is to simply run `sudo sigma-esf` within your Sigma rules folder.

There's not much configuration available yet other than:
* Disabling either file or process events (collecting *all* events can be quite CPU intensive so disable ones you don't need)
* Pointing to a directory of Sigma rules rather than using the current directory

```
Usage of sigma-esf:
  -monitor_files
    	Whether to monitor file events (default true)
  -monitor_processes
    	Whether to monitor process creation events (default true)
  -sigma_rules string
    	Path to a directory containing the Sigma rules to run (default ".")
```
