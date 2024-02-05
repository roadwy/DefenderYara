
rule TrojanDownloader_Win32_Renos_IJ{
	meta:
		description = "TrojanDownloader:Win32/Renos.IJ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 0c 50 68 00 14 2d 00 ff 75 90 01 01 ff 15 90 01 02 40 00 90 00 } //02 00 
		$a_03_1 = {c1 e8 1a c1 e6 06 8a 80 90 01 02 40 00 34 a0 90 00 } //02 00 
		$a_01_2 = {8a 06 04 60 0f b6 c0 83 c0 03 } //01 00 
		$a_01_3 = {77 07 3d 00 00 00 80 73 } //01 00 
		$a_03_4 = {68 58 4d 56 c7 85 90 01 02 ff ff 58 56 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}