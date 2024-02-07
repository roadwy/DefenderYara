
rule TrojanDownloader_O97M_Obfuse_CVD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.CVD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {4f 70 65 6e 20 22 43 3a 5c 44 69 73 6b 44 72 69 76 65 5c 31 5c 56 6f 6c 75 6d 65 5c 90 02 14 2e 62 61 74 22 90 00 } //01 00 
		$a_00_1 = {43 61 70 74 69 6f 6e 20 26 20 47 69 66 74 54 6f 50 61 70 70 65 72 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65 20 26 20 22 } //01 00  Caption & GiftToPapper.DefaultTargetFrame & "
		$a_03_2 = {44 69 73 6b 44 72 69 76 65 5c 31 5c 56 6f 6c 75 6d 65 5c 90 02 0a 5c 90 02 09 2e 64 6c 6c 90 0a 28 00 43 3a 5c 90 00 } //01 00 
		$a_03_3 = {63 6f 72 70 66 61 73 74 69 6e 64 75 73 74 72 69 65 73 2e 63 6f 6d 2f 90 02 09 2e 64 6c 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}