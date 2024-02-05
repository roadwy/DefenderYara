
rule TrojanDownloader_O97M_Emotet_SP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 43 72 65 61 74 65 } //01 00 
		$a_01_1 = {2b 20 28 22 53 54 41 52 54 55 22 29 } //01 00 
		$a_03_2 = {22 73 3a 57 90 02 06 69 90 02 06 6e 90 02 06 33 90 02 06 32 90 02 06 5f 90 02 06 50 90 02 12 72 90 02 06 6f 90 02 06 63 90 02 06 65 90 02 06 73 90 02 06 73 90 00 } //01 00 
		$a_03_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 90 05 0f 06 41 2d 5a 61 2d 7a 29 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}