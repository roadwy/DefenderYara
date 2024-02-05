
rule TrojanDownloader_Win32_Smac_B_dha{
	meta:
		description = "TrojanDownloader:Win32/Smac.B!dha,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 00 2d 00 44 00 6f 00 77 00 6e 00 4f 00 6e 00 6c 00 79 00 28 00 } //01 00 
		$a_01_1 = {78 00 2d 00 45 00 78 00 65 00 63 00 28 00 } //01 00 
		$a_01_2 = {45 00 78 00 65 00 63 00 75 00 74 00 65 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 21 00 } //01 00 
		$a_01_3 = {73 00 6d 00 61 00 63 00 3d 00 } //01 00 
		$a_01_4 = {26 00 73 00 72 00 65 00 73 00 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}