
rule TrojanDownloader_Win32_Unruy_H{
	meta:
		description = "TrojanDownloader:Win32/Unruy.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 25 73 2f 90 01 03 2f 69 6e 64 90 01 01 78 2e 70 68 70 3f 55 3d 25 64 40 25 64 40 25 64 40 25 64 40 25 64 40 25 73 90 00 } //01 00 
		$a_03_1 = {8b c1 99 f7 7d 90 01 01 8a 84 15 90 01 04 30 44 0d 90 01 01 41 83 f9 20 7c e9 90 00 } //01 00 
		$a_01_2 = {c6 00 20 40 c6 00 2e 40 c6 00 65 40 c6 00 78 40 c6 00 65 80 60 01 00 } //00 00 
	condition:
		any of ($a_*)
 
}