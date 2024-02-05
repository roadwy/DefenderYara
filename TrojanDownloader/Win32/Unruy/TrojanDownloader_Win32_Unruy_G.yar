
rule TrojanDownloader_Win32_Unruy_G{
	meta:
		description = "TrojanDownloader:Win32/Unruy.G,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 88 88 19 00 00 0f af c1 } //01 00 
		$a_01_1 = {c7 45 fc 81 a4 f4 01 } //02 00 
		$a_03_2 = {81 7d 9c 55 54 45 52 75 90 01 01 81 7d a0 4e 41 4d 45 90 00 } //02 00 
		$a_03_3 = {70 7a 62 70 75 90 01 01 83 90 01 01 06 74 90 00 } //02 00 
		$a_03_4 = {48 41 4c 39 75 90 01 01 83 90 01 01 07 0f 84 90 00 } //02 00 
		$a_03_5 = {49 4f 41 56 75 90 01 01 83 90 01 01 05 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}