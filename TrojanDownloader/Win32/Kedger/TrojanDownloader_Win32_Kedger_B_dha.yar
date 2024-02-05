
rule TrojanDownloader_Win32_Kedger_B_dha{
	meta:
		description = "TrojanDownloader:Win32/Kedger.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 75 6d 62 65 72 26 25 73 4f 72 64 65 72 26 25 73 43 6f 6e 74 65 6e 74 26 25 73 26 45 6e 64 41 6c 6c } //01 00 
		$a_01_1 = {3f 4e 75 6d 62 65 72 3d 25 73 31 26 53 69 74 65 49 64 3d 25 73 } //01 00 
		$a_01_2 = {49 70 3d 25 73 4e 61 3d 25 73 } //01 00 
		$a_01_3 = {55 70 46 61 69 6c 65 64 } //01 00 
		$a_01_4 = {55 70 53 75 63 63 65 73 73 } //01 00 
		$a_01_5 = {44 00 46 00 25 00 30 00 35 00 64 00 2e 00 74 00 6d 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}