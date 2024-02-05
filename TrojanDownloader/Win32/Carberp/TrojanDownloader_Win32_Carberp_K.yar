
rule TrojanDownloader_Win32_Carberp_K{
	meta:
		description = "TrojanDownloader:Win32/Carberp.K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 0c 17 32 0c 03 40 3b c5 88 0a 72 02 } //01 00 
		$a_01_1 = {8a 10 80 f2 4d 88 10 40 49 75 f5 } //01 00 
		$a_01_2 = {73 26 73 74 61 74 70 61 73 73 3d 25 73 } //01 00 
		$a_01_3 = {c6 44 24 10 63 66 c7 44 24 13 03 00 } //00 00 
	condition:
		any of ($a_*)
 
}