
rule TrojanDownloader_Win32_Mariofev_B{
	meta:
		description = "TrojanDownloader:Win32/Mariofev.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 1b ff 94 93 } //02 00 
		$a_01_1 = {53 83 c0 f3 53 50 56 ff 15 } //02 00 
		$a_01_2 = {25 73 3f 62 73 3d 25 64 26 6e 61 3d 25 64 26 75 61 63 3d 25 64 26 69 64 3d 25 73 } //01 00 
		$a_01_3 = {26 72 69 64 3d 25 64 } //01 00 
		$a_01_4 = {26 6c 6f 61 64 3d 30 78 25 2e 38 58 } //00 00 
	condition:
		any of ($a_*)
 
}