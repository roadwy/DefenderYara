
rule TrojanDownloader_Win32_Bibei_B{
	meta:
		description = "TrojanDownloader:Win32/Bibei.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 04 37 8a c8 c0 e9 04 c0 e0 04 0a c8 47 f6 d1 } //01 00 
		$a_01_1 = {b0 74 51 53 66 c7 07 50 00 c6 44 24 } //01 00 
		$a_01_2 = {bb 58 ae 89 18 74 14 39 58 04 } //00 00 
	condition:
		any of ($a_*)
 
}