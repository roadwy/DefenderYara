
rule TrojanDownloader_Win32_Agent_JW{
	meta:
		description = "TrojanDownloader:Win32/Agent.JW,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 74 6d 70 7a 5c 62 6f 6f 74 2e 63 6d 64 00 00 00 00 64 65 6c 20 2f 51 20 2f 46 20 63 3a 5c 74 6d 70 7a 5c 62 6f 6f 74 2e 63 6d 64 } //01 00 
		$a_01_1 = {63 3a 5c 70 73 2e 63 6d 64 00 00 00 64 65 6c 20 2f 51 20 2f 46 20 25 73 0a 00 00 00 64 65 6c 20 2f 51 20 2f 46 20 63 3a 5c 70 73 2e 63 6d 64 0a 00 00 00 00 63 3a 5c 6e 74 6c 64 72 78 64 73 00 } //01 00 
		$a_01_2 = {31 32 37 2e 30 2e 30 2e 31 20 75 70 64 61 74 65 73 2e 73 79 6d 61 6e 74 65 63 2e 63 6f 6d } //00 00  127.0.0.1 updates.symantec.com
	condition:
		any of ($a_*)
 
}