
rule TrojanDownloader_Win32_Agent_AAC{
	meta:
		description = "TrojanDownloader:Win32/Agent.AAC,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 70 63 69 68 64 64 2e 73 79 73 } //01 00 
		$a_01_1 = {53 79 73 74 65 6d 33 32 5c 55 73 65 72 69 6e 69 74 2e 65 78 65 } //01 00 
		$a_01_2 = {2e 6d 61 63 6b 74 } //01 00 
		$a_01_3 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //01 00 
		$a_01_4 = {43 72 65 61 74 65 53 65 72 76 69 63 65 41 } //01 00 
		$a_01_5 = {44 65 6c 65 74 65 53 65 72 76 69 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}