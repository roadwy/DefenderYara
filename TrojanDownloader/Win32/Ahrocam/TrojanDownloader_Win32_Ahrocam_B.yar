
rule TrojanDownloader_Win32_Ahrocam_B{
	meta:
		description = "TrojanDownloader:Win32/Ahrocam.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 8b 48 08 33 d2 66 8b 50 06 8b 74 24 18 51 52 33 c9 33 d2 66 8b 48 02 66 8b 10 51 52 68 90 01 04 56 e8 90 00 } //01 00 
		$a_01_1 = {72 75 6e 69 6e 66 6f 2e 65 78 65 } //01 00 
		$a_01_2 = {63 6f 6d 6d 61 6e 64 3d 4e 4f 26 72 65 73 75 6c 74 3d } //01 00 
		$a_01_3 = {68 74 74 70 2d 67 65 74 2d 64 65 6d 6f } //00 00 
	condition:
		any of ($a_*)
 
}