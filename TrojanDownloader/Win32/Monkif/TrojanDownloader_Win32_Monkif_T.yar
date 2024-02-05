
rule TrojanDownloader_Win32_Monkif_T{
	meta:
		description = "TrojanDownloader:Win32/Monkif.T,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 04 19 90 03 02 02 2a c2 28 d0 90 02 06 88 04 19 90 03 01 02 49 ff c9 90 03 01 02 75 0f 85 90 00 } //01 00 
		$a_03_1 = {c6 85 f8 ff ff ff e9 90 02 06 e8 90 00 } //01 00 
		$a_03_2 = {68 e8 ff ff ff 90 01 03 90 02 06 ff 15 90 01 04 81 f8 ff ff ff ff 90 02 06 0f 84 90 01 04 90 02 07 90 03 06 03 8d 85 f4 ff ff ff 8d 45 f4 90 00 } //01 00 
		$a_01_3 = {6d 73 79 75 76 2e 64 6c 6c 00 45 78 70 6f 72 74 31 00 } //01 00 
		$a_01_4 = {25 63 25 73 25 73 2e 70 68 70 25 63 25 73 25 63 25 73 00 00 70 68 6f 74 6f 2f } //00 00 
	condition:
		any of ($a_*)
 
}