
rule TrojanDownloader_Win32_Agent_MU{
	meta:
		description = "TrojanDownloader:Win32/Agent.MU,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6e 65 6d 65 73 69 73 2e 66 65 65 64 2e 70 61 72 6b 69 6e 67 73 70 61 2e 63 6f 6d 2f 4e 65 6d 65 73 69 73 } //01 00 
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 44 6f 6d 61 69 6e 53 70 61 5c 4e 65 6d 65 73 69 73 5c 43 6c 69 65 6e 74 5c 4e 65 6d 65 73 69 73 43 6c 69 65 6e 74 2e 65 78 65 } //01 00 
		$a_01_2 = {53 74 61 72 74 53 65 72 76 69 63 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}