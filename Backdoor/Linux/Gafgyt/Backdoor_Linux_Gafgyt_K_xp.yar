
rule Backdoor_Linux_Gafgyt_K_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.K!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 43 41 4e 4e 45 52 20 53 54 41 52 54 45 44 } //01 00  SCANNER STARTED
		$a_00_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 70 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 45 43 48 4f 42 4f 54 3b 20 3e 20 45 43 48 4f 42 4f 54 3b 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 45 43 48 4f 42 4f 54 3b 20 45 43 48 4f 42 4f 54 } //01 00  /bin/busybox cp /bin/busybox ECHOBOT; > ECHOBOT; /bin/busybox chmod 777 ECHOBOT; ECHOBOT
		$a_00_2 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 45 43 48 4f 42 4f 54 3b 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 74 66 74 70 3b 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 } //01 00  /bin/busybox ECHOBOT; /bin/busybox tftp; /bin/busybox wget
		$a_00_3 = {45 43 48 4f 42 4f 54 5d 20 44 52 4f 50 50 49 4e 47 20 57 47 45 54 2f 54 46 54 50 20 4d 41 4c 57 41 52 45 } //01 00  ECHOBOT] DROPPING WGET/TFTP MALWARE
		$a_02_4 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 90 02 03 2e 90 02 03 2e 90 02 03 2e 90 02 03 2f 90 02 10 2e 73 68 3b 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 2b 78 20 90 02 10 2e 73 68 3b 20 73 68 20 90 02 10 2e 73 68 90 00 } //01 00 
		$a_00_5 = {48 4f 4c 44 40 44 44 6f 53 5d 20 46 6c 6f 6f 64 69 6e 67 20 25 73 3a 25 64 20 66 6f 72 20 25 64 20 73 65 63 6f 6e 64 73 } //01 00  HOLD@DDoS] Flooding %s:%d for %d seconds
		$a_00_6 = {77 67 65 74 20 49 50 2f 62 72 69 63 6b 65 72 2e 73 68 } //01 00  wget IP/bricker.sh
		$a_00_7 = {49 4e 53 54 41 4c 4c 49 4e 47 20 42 52 49 43 4b 45 52 } //01 00  INSTALLING BRICKER
		$a_00_8 = {49 4e 53 54 41 4c 4c 49 4e 47 20 4d 49 4e 45 52 } //01 00  INSTALLING MINER
		$a_00_9 = {42 72 69 63 6b 69 6e 67 20 41 6c 6c 20 54 68 65 20 53 6b 69 64 73 20 42 6f 74 73 } //00 00  Bricking All The Skids Bots
		$a_00_10 = {5d 04 00 } //00 24 
	condition:
		any of ($a_*)
 
}