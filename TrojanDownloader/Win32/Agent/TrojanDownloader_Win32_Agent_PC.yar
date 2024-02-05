
rule TrojanDownloader_Win32_Agent_PC{
	meta:
		description = "TrojanDownloader:Win32/Agent.PC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 64 53 6a 04 8d 4c 24 20 51 8d 44 24 30 6a ff } //01 00 
		$a_01_1 = {83 e0 0f 0f b7 04 47 83 c1 02 8b e9 66 89 45 00 0f b6 2a 83 c1 02 c1 ed 04 66 8b 2c 6f 8b c1 66 89 28 } //01 00 
		$a_00_2 = {64 00 31 00 2e 00 64 00 6f 00 77 00 6e 00 78 00 69 00 61 00 2e 00 6e 00 65 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}