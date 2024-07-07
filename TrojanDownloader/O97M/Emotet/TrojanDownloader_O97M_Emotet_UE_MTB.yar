
rule TrojanDownloader_O97M_Emotet_UE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.UE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {46 75 6e 63 74 69 6f 6e 20 90 02 20 28 29 90 02 08 49 66 90 00 } //1
		$a_03_1 = {44 6f 20 57 68 69 6c 65 20 90 02 40 2e 20 5f 90 00 } //1
		$a_03_2 = {43 72 65 61 74 65 28 90 02 20 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //1
		$a_03_3 = {2e 47 72 6f 75 70 4e 61 6d 65 90 02 20 20 3d 20 53 70 6c 69 74 28 90 02 20 20 2b 20 54 72 69 6d 28 90 02 10 29 2c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}