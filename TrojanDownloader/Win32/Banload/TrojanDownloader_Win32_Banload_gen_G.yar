
rule TrojanDownloader_Win32_Banload_gen_G{
	meta:
		description = "TrojanDownloader:Win32/Banload.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0f 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {63 6f 6e 66 69 67 65 78 2e 64 6c 6c 00 90 05 03 01 00 68 74 74 70 3a 2f 2f 90 02 30 2f 63 6f 6e 66 69 67 90 02 02 2e 74 78 74 00 90 00 } //04 00 
		$a_01_1 = {47 65 72 61 6c 00 } //01 00 
		$a_01_2 = {61 75 74 6f 6d 73 6e 00 } //01 00 
		$a_01_3 = {61 75 74 6f 72 6b 00 } //01 00 
		$a_01_4 = {4d 65 6e 73 61 67 65 6d 48 6f 74 6d 61 69 6c 00 } //01 00 
		$a_01_5 = {41 75 74 65 6e 74 69 63 61 63 61 6f 48 6f 74 6d 61 69 6c 00 } //0a 00 
		$a_03_6 = {6a 00 6a 00 8d 85 90 01 02 ff ff e8 90 01 04 ff b5 90 01 02 ff ff 68 90 01 04 68 90 01 04 8d 85 90 01 02 ff ff ba 03 00 00 00 e8 90 01 04 8b 85 90 01 02 ff ff e8 90 01 04 50 68 90 01 04 6a 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}