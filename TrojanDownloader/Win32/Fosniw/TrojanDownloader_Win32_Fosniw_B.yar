
rule TrojanDownloader_Win32_Fosniw_B{
	meta:
		description = "TrojanDownloader:Win32/Fosniw.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 0d 68 f4 01 00 00 ff d5 46 83 fe 78 7c c9 } //01 00 
		$a_03_1 = {c6 44 24 0c 37 89 54 24 90 01 01 66 89 44 24 90 01 01 e8 90 01 04 33 f6 80 7c 24 90 01 01 00 0f 86 90 01 04 8d 64 24 00 6a 40 8d 54 24 0c 6a 00 52 e8 90 02 09 83 c4 0c 8d 4c 24 90 01 01 51 c6 44 24 0c 32 90 00 } //01 00 
		$a_03_2 = {8b 54 24 10 80 f1 90 01 01 88 0c 90 01 02 83 90 01 01 04 90 02 04 3b 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}