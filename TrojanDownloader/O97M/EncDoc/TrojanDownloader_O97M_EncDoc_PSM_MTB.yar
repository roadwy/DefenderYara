
rule TrojanDownloader_O97M_EncDoc_PSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 72 68 77 73 65 31 } //1 Frhwse1
		$a_01_1 = {52 47 68 6a 67 6a 74 31 } //1 RGhjgjt1
		$a_01_2 = {52 47 68 6a 67 6a 74 32 } //1 RGhjgjt2
		$a_01_3 = {54 54 47 45 48 45 48 45 48 46 48 44 47 } //1 TTGEHEHEHFHDG
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_PSM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 70 6c 61 63 65 28 43 65 6c 6c 73 28 31 30 31 2c 20 34 29 2c 20 22 6a 71 77 69 } //1 Replace(Cells(101, 4), "jqwi
		$a_01_1 = {52 65 70 6c 61 63 65 28 43 65 6c 6c 73 28 31 30 30 2c 20 33 29 2c 20 22 6f 65 69 72 } //1 Replace(Cells(100, 3), "oeir
		$a_01_2 = {73 64 68 6a 6c 33 6b 6a 67 68 6b 6a 67 } //1 sdhjl3kjghkjg
		$a_01_3 = {66 68 6b 33 20 33 67 34 6b 75 65 73 67 } //1 fhk3 3g4kuesg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}