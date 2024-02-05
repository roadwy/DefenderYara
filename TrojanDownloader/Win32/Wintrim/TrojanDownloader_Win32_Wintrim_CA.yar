
rule TrojanDownloader_Win32_Wintrim_CA{
	meta:
		description = "TrojanDownloader:Win32/Wintrim.CA,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {dd d8 c3 90 } //01 00 
		$a_01_1 = {dd d8 d9 41 } //01 00 
		$a_01_2 = {d9 c0 d8 c9 } //05 00 
		$a_03_3 = {2c 31 00 00 90 09 02 00 81 90 04 01 03 f8 2d ff 90 01 04 90 02 22 0f 8c 90 01 02 ff ff 90 00 } //05 00 
		$a_03_4 = {2c 31 00 00 90 09 01 00 3d 90 01 04 90 02 22 0f 8c 90 01 02 ff ff 90 00 } //0a 00 
		$a_01_5 = {df e0 f6 c4 40 75 } //00 00 
	condition:
		any of ($a_*)
 
}