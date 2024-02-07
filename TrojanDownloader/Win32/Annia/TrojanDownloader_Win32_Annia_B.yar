
rule TrojanDownloader_Win32_Annia_B{
	meta:
		description = "TrojanDownloader:Win32/Annia.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {bb 82 23 00 00 89 90 01 03 8b f3 ff 90 01 03 ff d5 4e 75 f7 90 00 } //01 00 
		$a_01_1 = {75 67 67 63 3a 2f 2f 34 36 2e 31 34 38 2e 32 30 2e 35 32 2f 79 78 2e 72 6b 72 } //01 00  uggc://46.148.20.52/yx.rkr
		$a_03_2 = {53 53 6a 03 53 6a 03 53 68 90 01 02 40 00 c7 45 64 90 01 02 40 00 c7 45 68 90 01 02 40 00 c7 45 6c 90 01 02 40 00 89 5d 70 ff 15 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}