
rule TrojanDownloader_Win32_Zirit_A{
	meta:
		description = "TrojanDownloader:Win32/Zirit.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c2 28 8b 02 03 05 90 01 03 00 c7 44 24 28 90 01 03 00 ff e0 61 6a 00 ff 15 90 01 03 00 90 00 } //01 00 
		$a_03_1 = {b9 03 00 00 00 8b 06 35 0d 0d 0d 0d 89 06 83 c6 04 e2 f2 be 90 01 03 00 b9 0c 00 00 00 f3 a4 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 68 90 01 03 00 90 00 } //01 00 
		$a_03_2 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 68 90 01 03 00 ff 15 90 01 03 00 a3 90 01 03 00 6a 02 6a 00 6a fc ff 35 90 01 03 00 ff 15 90 01 03 00 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}