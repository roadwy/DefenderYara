
rule TrojanDownloader_Win32_Unruy_T{
	meta:
		description = "TrojanDownloader:Win32/Unruy.T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 81 48 64 01 00 8d 91 48 64 01 00 56 8d 70 01 8b c6 69 c0 30 01 00 00 8b 04 08 89 32 5e c3 } //01 00 
		$a_01_1 = {3d 00 28 00 00 73 05 } //01 00 
		$a_01_2 = {c6 45 fc 2e c6 45 fd 2e c6 45 fe 2e ff 90 2c 01 00 00 f7 d8 1b c0 40 c9 c3 } //00 00 
	condition:
		any of ($a_*)
 
}