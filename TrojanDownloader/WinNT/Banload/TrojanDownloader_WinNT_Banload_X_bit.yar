
rule TrojanDownloader_WinNT_Banload_X_bit{
	meta:
		description = "TrojanDownloader:WinNT/Banload.X!bit,SIGNATURE_TYPE_JAVAHSTR_EXT,0f 00 0f 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0f 4c 6c 6f 61 64 65 72 2f 4c 6f 61 64 65 72 } //0a 00 
		$a_00_1 = {61 33 41 35 42 44 36 39 46 41 31 39 30 30 35 42 42 32 2e 7a 69 70 } //01 00  a3A5BD69FA19005BB2.zip
		$a_00_2 = {08 44 6f 77 6e 6c 6f 61 64 } //01 00 
		$a_00_3 = {08 65 78 74 72 61 74 6f 72 } //01 00 
		$a_00_4 = {07 65 78 65 63 75 74 65 } //01 00  攇數畣整
		$a_00_5 = {06 64 65 6c 65 74 65 } //01 00 
		$a_02_6 = {63 6d 64 2e 65 78 65 20 2f 90 02 10 6c 6f 63 61 6c 61 70 70 64 61 74 61 90 02 30 2e 65 78 65 90 00 } //00 00 
		$a_00_7 = {5d 04 00 00 76 } //af 03 
	condition:
		any of ($a_*)
 
}