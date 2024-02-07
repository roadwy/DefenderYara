
rule TrojanProxy_Win32_Raser{
	meta:
		description = "TrojanProxy:Win32/Raser,SIGNATURE_TYPE_PEHSTR,79 00 79 00 0e 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 72 6f 78 79 2d 41 75 74 68 65 6e 74 69 63 61 74 65 3a 20 42 61 73 69 63 20 72 65 61 6c 6d 3d 22 70 72 6f 78 79 22 } //0a 00  Proxy-Authenticate: Basic realm="proxy"
		$a_01_1 = {66 74 70 40 79 61 2e 72 75 } //0a 00  ftp@ya.ru
		$a_01_2 = {53 79 73 74 65 6d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 47 6c 6f 62 61 6c 6c 79 4f 70 65 6e 50 6f 72 74 73 5c 4c 69 73 74 } //0a 00  System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\GloballyOpenPorts\List
		$a_01_3 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 29 } //0a 00  Mozilla/4.0 (compatible)
		$a_01_4 = {25 73 2f 72 2e 70 68 70 3f } //0a 00  %s/r.php?
		$a_01_5 = {63 68 65 63 6b 2e 64 61 74 } //0a 00  check.dat
		$a_01_6 = {50 41 53 53 20 25 2e 36 34 73 } //0a 00  PASS %.64s
		$a_01_7 = {55 53 45 52 20 25 2e 33 32 73 } //0a 00  USER %.32s
		$a_01_8 = {3c 62 6f 64 79 3e 3c 68 32 3e 34 30 37 20 50 72 6f 78 79 20 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 20 52 65 71 75 69 72 65 64 3c 2f 68 32 3e 3c 68 33 3e 41 63 63 65 73 73 20 74 6f 20 72 65 71 75 65 73 74 65 64 20 72 65 73 6f 75 72 63 65 20 64 69 73 61 6c 6c 6f 77 65 64 20 62 79 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 20 6f 72 20 79 6f 75 20 6e 65 65 64 20 76 61 6c 69 64 20 75 73 65 72 6e 61 6d 65 2f 70 61 73 73 77 6f 72 64 20 74 6f 20 75 73 65 20 74 68 69 73 20 72 65 73 6f 75 72 63 65 3c 2f 68 33 3e 3c 2f 62 6f 64 79 3e 3c 2f 68 74 6d 6c 3e } //0a 00  <body><h2>407 Proxy Authentication Required</h2><h3>Access to requested resource disallowed by administrator or you need valid username/password to use this resource</h3></body></html>
		$a_01_9 = {48 54 54 50 2f 31 2e 30 20 35 30 32 20 42 61 64 20 47 61 74 65 77 61 79 } //0a 00  HTTP/1.0 502 Bad Gateway
		$a_01_10 = {3c 68 74 6d 6c 3e 3c 68 65 61 64 3e 3c 74 69 74 6c 65 3e 34 30 30 20 42 61 64 20 52 65 71 75 65 73 74 3c 2f 74 69 74 6c 65 3e 3c 2f 68 65 61 64 3e } //0a 00  <html><head><title>400 Bad Request</title></head>
		$a_01_11 = {3c 62 6f 64 79 3e 3c 68 32 3e 35 30 32 20 42 61 64 20 47 61 74 65 77 61 79 3c 2f 68 32 3e 3c 68 33 3e 48 6f 73 74 20 4e 6f 74 20 46 6f 75 6e 64 20 6f 72 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 66 61 69 6c 65 64 3c 2f 68 33 3e 3c 2f 62 6f 64 79 3e 3c 2f 68 74 6d 6c 3e } //01 00  <body><h2>502 Bad Gateway</h2><h3>Host Not Found or connection failed</h3></body></html>
		$a_01_12 = {70 72 65 66 63 5f 25 75 2e 65 78 65 } //01 00  prefc_%u.exe
		$a_01_13 = {70 72 65 66 63 25 75 2e 65 78 65 } //00 00  prefc%u.exe
	condition:
		any of ($a_*)
 
}