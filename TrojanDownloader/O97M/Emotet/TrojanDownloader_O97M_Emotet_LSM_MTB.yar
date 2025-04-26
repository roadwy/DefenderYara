
rule TrojanDownloader_O97M_Emotet_LSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.LSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 6f 72 6b 73 68 65 65 74 73 28 22 6f 75 6f 69 22 29 } //1 Worksheets("ouoi")
		$a_01_1 = {57 6f 72 6b 73 68 65 65 74 73 28 22 76 67 75 37 79 22 29 } //1 Worksheets("vgu7y")
		$a_01_2 = {57 6f 72 6b 73 68 65 65 74 73 28 22 6e 75 75 69 22 29 } //1 Worksheets("nuui")
		$a_01_3 = {57 6f 72 6b 73 68 65 65 74 73 28 22 6e 6a 6f 69 22 29 } //1 Worksheets("njoi")
		$a_01_4 = {57 6f 72 6b 73 68 65 65 74 73 28 22 2c 68 75 38 22 29 } //1 Worksheets(",hu8")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}