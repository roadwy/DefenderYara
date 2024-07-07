
rule TrojanDownloader_O97M_Emotet_RVU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RVU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {52 45 54 55 90 01 03 28 29 90 01 03 52 4e 90 01 03 65 90 01 03 22 2c 22 90 01 03 64 6c 65 5f 6f 6c 64 2f 39 67 69 67 6c 48 72 67 32 74 2f 90 00 } //1
		$a_03_1 = {52 45 54 55 90 02 32 2f 4f 6c 22 26 22 64 2f 55 22 26 22 6c 66 22 26 22 47 47 22 26 22 4e 4e 22 26 22 36 78 22 26 22 62 61 22 26 22 75 2f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}