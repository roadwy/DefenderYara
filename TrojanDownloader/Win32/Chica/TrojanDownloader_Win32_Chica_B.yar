
rule TrojanDownloader_Win32_Chica_B{
	meta:
		description = "TrojanDownloader:Win32/Chica.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 04 00 "
		
	strings :
		$a_02_0 = {8d 55 d8 a1 68 6a 41 00 0f b7 40 08 e8 90 01 01 35 ff ff ff 75 d8 68 90 01 01 44 41 00 a1 58 6a 41 00 33 d2 52 50 8d 45 d4 e8 90 00 } //01 00 
		$a_00_1 = {2f 62 6f 74 2f 6e 65 77 2e 70 68 70 } //01 00 
		$a_00_2 = {2f 62 6f 74 2f 67 65 74 2e 70 68 70 3f 73 6f 63 6b 73 3d } //01 00 
		$a_00_3 = {2f 62 6f 74 2f 61 64 64 2e 70 68 70 3f 69 64 3d } //01 00 
		$a_00_4 = {77 69 6e 6c 6f 61 64 2e 69 6e 69 } //00 00 
	condition:
		any of ($a_*)
 
}