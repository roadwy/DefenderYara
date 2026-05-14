
rule Backdoor_Win64_GoverKick_A_dha{
	meta:
		description = "Backdoor:Win64/GoverKick.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 08 00 00 "
		
	strings :
		$a_01_0 = {74 65 36 34 2e 64 6c 6c 00 47 65 74 49 6d 61 67 65 00 48 65 6c 6c 6f 00 52 75 6e 44 4c 4c 57 } //2
		$a_01_1 = {54 61 73 6b 20 71 75 65 75 65 20 66 75 6c 6c 2c 20 72 65 6a 65 63 74 69 6e 67 3a 20 25 73 } //1 Task queue full, rejecting: %s
		$a_01_2 = {50 72 6f 78 79 20 72 65 74 75 72 6e 65 64 20 65 72 72 6f 72 20 73 74 61 74 75 73 3a 20 25 64 } //1 Proxy returned error status: %d
		$a_01_3 = {54 61 73 6b 20 71 75 65 75 65 64 3a 20 25 73 20 28 49 44 3a 20 25 73 29 } //1 Task queued: %s (ID: %s)
		$a_01_4 = {47 65 6e 65 72 61 74 65 64 20 68 6f 73 74 20 66 69 6e 67 65 72 70 72 69 6e 74 3a 20 48 6f 73 74 6e 61 6d 65 3d 25 73 2c 20 4d 41 43 3d 25 73 2c 20 42 6f 6f 74 54 69 6d 65 3d 25 73 } //1 Generated host fingerprint: Hostname=%s, MAC=%s, BootTime=%s
		$a_01_5 = {53 65 6e 64 69 6e 67 20 72 65 67 69 73 74 72 61 74 69 6f 6e 3a 20 49 44 3d 25 73 2c 20 48 6f 73 74 49 44 3d 25 73 } //1 Sending registration: ID=%s, HostID=%s
		$a_01_6 = {47 6c 6f 62 61 6c 5c 4d 79 47 6f 41 70 70 55 6e 69 71 75 65 4d 75 74 65 78 4e 61 6d 65 } //1 Global\MyGoAppUniqueMutexName
		$a_01_7 = {70 61 74 68 09 74 65 36 34 0a 6d 6f 64 09 74 65 36 34 09 28 64 65 76 65 6c 29 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=2
 
}