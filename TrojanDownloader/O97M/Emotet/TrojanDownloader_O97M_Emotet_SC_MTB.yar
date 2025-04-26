
rule TrojanDownloader_O97M_Emotet_SC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 20 90 05 0f 06 41 2d 5a 61 2d 7a 2e } //1
		$a_03_1 = {46 75 6e 63 74 69 6f 6e [0-14] 28 29 90 0c 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 } //1
		$a_03_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 90 05 0f 06 41 2d 5a 61 2d 7a 29 29 } //1
		$a_03_3 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 90 0c 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}