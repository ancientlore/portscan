# portscan

`portscan` is a simple TCP port scanner written in Go.

	Usage of portscan:
	  -host string
	    	Host or IP to scan (default "localhost")
	  -range string
	    	Port ranges e.g. 80,443,200-1000,8000-9000 (default "80,443")
	  -threads int
	    	Threads to use (default 100)
	  -timeout duration
	    	Timeout per port (default 1s)
	  -verbose
	    	Show errors for failed ports

