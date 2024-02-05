
rule TrojanDownloader_Win32_Renos_FU{
	meta:
		description = "TrojanDownloader:Win32/Renos.FU,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 02 00 "
		
	strings :
		$a_00_0 = {5c 5c 2e 5c 43 3a } //02 00 
		$a_03_1 = {68 00 14 2d 00 90 09 03 00 6a 0c 90 00 } //01 00 
		$a_01_2 = {68 58 4d 56 0f 94 c0 } //01 00 
		$a_01_3 = {68 4d 56 00 00 68 68 58 00 00 } //02 00 
		$a_03_4 = {40 3d ff 00 00 00 7c ea 90 09 10 00 90 02 0a d1 88 90 00 } //01 00 
		$a_01_5 = {8a 8d 00 04 00 00 8d 85 00 04 00 00 3a cb 75 16 38 1e 74 12 68 00 04 00 00 } //01 00 
		$a_01_6 = {25 6c 75 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}