
rule TrojanDownloader_O97M_Gen_BB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gen.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 73 74 2e 65 78 65 } //1 svchst.exe
		$a_03_1 = {68 74 74 70 73 3a 2f 2f 90 02 40 2f 73 76 63 68 73 74 2e 65 78 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}