
rule TrojanDownloader_Win32_Agent_MG_MTB{
	meta:
		description = "TrojanDownloader:Win32/Agent.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 74 6a 2e 67 6f 67 6f 32 30 32 31 2e 78 79 7a 2f } //01 00 
		$a_01_1 = {5c 57 49 4e 44 4f 57 53 5c 54 65 6d 70 5c 4d 70 43 7a 30 31 2e 74 6d 70 } //01 00 
		$a_01_2 = {5c 54 45 4d 50 5c 7e 31 7a 32 33 2e 74 6d 70 } //01 00 
		$a_01_3 = {53 6c 65 65 70 } //01 00 
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_01_5 = {70 61 73 73 54 68 72 6f 75 67 68 2e 70 64 62 } //01 00 
		$a_01_6 = {43 72 65 61 74 65 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}