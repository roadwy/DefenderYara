
rule TrojanDownloader_O97M_EncDoc_PSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 72 68 77 73 65 31 } //01 00 
		$a_01_1 = {52 47 68 6a 67 6a 74 31 } //01 00 
		$a_01_2 = {52 47 68 6a 67 6a 74 32 } //01 00 
		$a_01_3 = {54 54 47 45 48 45 48 45 48 46 48 44 47 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_EncDoc_PSM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 70 6c 61 63 65 28 43 65 6c 6c 73 28 31 30 31 2c 20 34 29 2c 20 22 6a 71 77 69 } //01 00 
		$a_01_1 = {52 65 70 6c 61 63 65 28 43 65 6c 6c 73 28 31 30 30 2c 20 33 29 2c 20 22 6f 65 69 72 } //01 00 
		$a_01_2 = {73 64 68 6a 6c 33 6b 6a 67 68 6b 6a 67 } //01 00 
		$a_01_3 = {66 68 6b 33 20 33 67 34 6b 75 65 73 67 } //00 00 
	condition:
		any of ($a_*)
 
}