
rule TrojanDownloader_Win32_Unruy_R{
	meta:
		description = "TrojanDownloader:Win32/Unruy.R,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {30 01 00 00 e8 90 01 02 00 00 3b 90 01 01 90 13 8d 90 00 } //01 00 
		$a_01_1 = {3d 00 28 00 00 72 } //01 00 
		$a_03_2 = {3d ff 7f 00 00 89 90 02 04 75 90 01 01 c7 90 02 03 fe 7f 00 00 db 90 00 } //01 00 
		$a_03_3 = {83 f8 03 74 90 01 01 90 03 03 02 83 f8 01 3b c5 8d 90 02 05 75 90 01 01 e8 90 01 02 00 00 85 c0 75 90 01 01 8d 90 02 05 e8 90 01 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}