
rule TrojanDownloader_Win32_Karagany_F{
	meta:
		description = "TrojanDownloader:Win32/Karagany.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4f 70 65 72 61 2f 90 10 02 00 2e 90 0f 02 00 20 50 90 03 00 01 72 65 73 74 6f 2f 90 00 } //01 00 
		$a_03_1 = {21 23 4c 44 52 90 01 03 2e 62 61 74 90 00 } //01 00 
		$a_03_2 = {b9 e8 03 00 00 f7 f1 3d 58 02 00 00 76 90 01 01 68 b4 05 00 00 90 00 } //01 00 
		$a_01_3 = {8b 51 04 83 ea 08 d1 ea 89 55 f4 8b 45 08 83 c0 08 } //00 00 
	condition:
		any of ($a_*)
 
}