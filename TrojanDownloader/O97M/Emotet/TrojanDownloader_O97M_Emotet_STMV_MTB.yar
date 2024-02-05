
rule TrojanDownloader_O97M_Emotet_STMV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.STMV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6b 6d 6f 64 6f 2e 75 73 2f 63 67 69 2d 62 69 6e 2f 44 2f 22 } //01 00 
		$a_01_1 = {3a 2f 2f 74 72 61 76 65 6c 2e 70 6b 6e 32 2e 67 6f 2e 74 68 2f 69 6d 67 2f 41 4d 71 58 31 6e 46 64 45 4f 6e 6d 6b 2f 22 } //01 00 
		$a_01_2 = {3a 2f 2f 74 72 69 76 65 74 2e 63 6f 2e 6a 70 2f 63 73 73 2f 69 74 6d 58 56 35 35 44 6e 44 6e 38 4d 79 58 64 65 45 38 2f 22 } //01 00 
		$a_01_3 = {3a 2f 2f 74 72 79 73 74 2e 63 7a 2f 73 71 6c 75 70 6c 6f 61 64 73 2f 71 74 30 45 78 74 68 47 32 4e 6e 7a 2f 22 } //00 00 
	condition:
		any of ($a_*)
 
}