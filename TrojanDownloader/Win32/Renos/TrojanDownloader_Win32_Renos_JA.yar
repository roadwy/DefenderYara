
rule TrojanDownloader_Win32_Renos_JA{
	meta:
		description = "TrojanDownloader:Win32/Renos.JA,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 83 c7 04 83 fb 0a 72 } //02 00 
		$a_03_1 = {83 f9 05 7d 13 8a 94 0d 90 01 02 ff ff 81 f2 90 01 01 00 00 00 88 14 01 41 eb e2 90 00 } //02 00 
		$a_03_2 = {6a 0c 50 68 00 14 2d 00 ff 75 90 01 01 ff 15 90 01 03 00 90 00 } //02 00 
		$a_03_3 = {0f be 09 83 f1 90 01 01 83 f9 42 0f 84 90 01 02 00 00 83 f9 4f 74 0b 83 f9 55 0f 84 90 01 02 00 00 90 00 } //01 00 
		$a_01_4 = {8a 5a 03 80 fb 3d 0f 85 8a 00 00 00 8a 42 02 3a c3 75 38 } //01 00 
		$a_01_5 = {77 07 3d 00 00 00 80 73 } //01 00 
		$a_03_6 = {68 58 4d 56 c7 85 90 01 02 ff ff 58 56 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}