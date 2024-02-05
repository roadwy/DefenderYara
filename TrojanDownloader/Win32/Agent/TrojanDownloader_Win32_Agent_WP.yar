
rule TrojanDownloader_Win32_Agent_WP{
	meta:
		description = "TrojanDownloader:Win32/Agent.WP,SIGNATURE_TYPE_PEHSTR,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 68 65 6c 6c 5f 74 72 61 79 77 6e 64 00 00 00 25 73 5c 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 79 } //01 00 
		$a_01_1 = {47 47 00 00 50 50 00 00 6f 70 65 6e 00 00 00 00 46 46 00 00 68 74 74 70 3a 2f 2f 77 } //01 00 
		$a_01_2 = {8a 10 8a 1e 8a ca 3a d3 75 1e 84 c9 74 16 8a 50 01 8a 5e 01 8a ca 3a d3 75 0e } //01 00 
		$a_01_3 = {50 ff 73 30 ff 53 10 ff 75 10 ff 53 08 85 c0 0f 94 45 ff 58 74 34 } //00 00 
	condition:
		any of ($a_*)
 
}