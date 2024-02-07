
rule TrojanDownloader_O97M_EncDoc_RVO_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RVO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {52 65 70 6c 61 63 65 28 53 74 72 52 65 76 65 72 73 65 28 22 74 78 74 90 01 16 63 6e 45 2f 31 2f 38 31 32 90 01 16 35 33 32 90 01 16 37 37 31 90 01 16 38 30 31 2f 2f 3a 70 74 74 68 22 29 2c 20 22 90 01 16 22 2c 20 22 2e 22 29 90 00 } //01 00 
		$a_03_1 = {2e 43 72 65 61 74 65 28 90 01 16 20 2b 20 90 01 16 20 2b 20 90 01 16 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 70 72 6f 63 65 73 73 69 64 29 90 00 } //01 00 
		$a_01_2 = {57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //00 00  Workbook_Open()
	condition:
		any of ($a_*)
 
}