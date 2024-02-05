
rule TrojanDownloader_Win32_Unruy_A{
	meta:
		description = "TrojanDownloader:Win32/Unruy.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {80 7d 00 58 75 6a 80 7d ff 50 75 64 80 7d fe 55 75 5e a1 } //02 00 
		$a_03_1 = {59 85 c0 74 3d 68 90 01 02 40 00 50 e8 90 01 02 00 00 ff 35 90 00 } //04 00 
		$a_03_2 = {80 38 3d 75 03 c6 00 00 ff 45 90 01 01 8d 45 90 01 01 50 ff d6 39 45 90 01 01 72 e3 68 90 01 04 8d 45 90 01 01 50 c6 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}