
rule TrojanDownloader_O97M_EncDoc_ASP_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ASP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 22 26 22 74 22 26 22 74 22 26 22 70 [0-20] 3a 22 26 22 2f 22 26 22 2f [0-60] 22 26 22 [0-60] 2e [0-15] 2f [0-45] 2f 61 22 26 22 6c 22 26 22 74 22 26 22 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}