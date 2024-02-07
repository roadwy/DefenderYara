
rule TrojanDownloader_Win32_Tapivat_B{
	meta:
		description = "TrojanDownloader:Win32/Tapivat.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {6a 03 6a 00 6a 00 68 00 00 00 80 56 ff 15 90 01 02 00 10 6a 00 50 a3 90 01 02 00 10 ff 15 90 01 02 00 10 6a 04 68 00 30 00 00 50 6a 00 90 00 } //03 00 
		$a_03_1 = {99 b9 1a 00 00 00 68 dc 05 00 00 f7 f9 8b da 80 c3 41 ff 15 90 01 02 00 10 6a 00 90 00 } //03 00 
		$a_01_2 = {85 c0 74 16 6a 32 ff d7 46 83 fe 05 72 da } //01 00 
		$a_01_3 = {41 6e 74 69 52 65 62 6f 6f 74 44 65 6c 00 } //01 00  湁楴敒潢瑯敄l
		$a_01_4 = {52 65 61 64 4f 6c 64 49 6e 69 46 69 6c 65 } //00 00  ReadOldIniFile
	condition:
		any of ($a_*)
 
}