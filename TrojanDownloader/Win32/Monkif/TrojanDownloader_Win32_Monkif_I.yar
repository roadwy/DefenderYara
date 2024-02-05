
rule TrojanDownloader_Win32_Monkif_I{
	meta:
		description = "TrojanDownloader:Win32/Monkif.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c1 99 f7 fb 83 c1 01 8a 04 2a 30 44 31 ff 3b cf 7c ed } //01 00 
		$a_01_1 = {b2 15 80 3c 31 ff 75 0e 38 54 31 01 } //02 00 
		$a_01_2 = {57 56 ff d5 33 c9 85 ff 76 1a 8a 04 31 8a d0 f6 d2 32 d0 80 e2 14 f6 d0 32 d0 88 14 31 } //00 00 
	condition:
		any of ($a_*)
 
}