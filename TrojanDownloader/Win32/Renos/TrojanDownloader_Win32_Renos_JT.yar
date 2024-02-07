
rule TrojanDownloader_Win32_Renos_JT{
	meta:
		description = "TrojanDownloader:Win32/Renos.JT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 04 19 88 03 } //01 00 
		$a_01_1 = {0f 01 4c 24 } //01 00 
		$a_01_2 = {68 58 4d 56 } //01 00  hXMV
		$a_03_3 = {0f b6 c0 83 c0 90 01 01 24 90 00 } //01 00 
		$a_00_4 = {77 67 65 74 20 33 2e 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}