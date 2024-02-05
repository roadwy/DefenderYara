
rule TrojanDownloader_Win32_Harnig_P{
	meta:
		description = "TrojanDownloader:Win32/Harnig.P,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {0f 01 4d f9 8b 45 fb 25 00 00 f0 ff 3d 00 00 c0 ff 75 04 c6 45 ff 01 0f b6 45 ff } //01 00 
		$a_02_1 = {51 50 ff 15 90 01 04 6a 04 89 45 08 8d 45 e0 50 6a 02 ff 75 f4 ff 15 90 00 } //01 00 
		$a_00_2 = {8b 11 b8 20 20 20 20 0b d0 81 fa 65 78 70 6c 75 77 8b 51 04 0b d0 81 fa 6f 72 65 72 75 6a 8b 49 08 0b c8 81 f9 2e 65 78 65 } //01 00 
		$a_02_3 = {2e 70 68 70 3f 61 64 76 3d 61 64 76 90 02 05 26 63 6f 64 65 31 3d 25 73 26 63 6f 64 65 32 3d 25 73 26 69 64 3d 25 64 26 70 3d 25 73 00 90 00 } //01 00 
		$a_01_4 = {68 74 74 70 3a 2f 2f 63 63 66 61 69 72 79 2e 63 6f 6d 2f } //00 00 
	condition:
		any of ($a_*)
 
}