
rule TrojanDownloader_O97M_EncDoc_PDQW_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PDQW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 65 74 64 72 64 2e 4f 4f 4f 4f 43 43 43 43 58 58 58 58 } //1 Cetdrd.OOOOCCCCXXXX
		$a_01_1 = {34 34 36 39 39 2c 36 32 38 32 37 33 30 33 32 34 2e 64 61 74 } //1 44699,6282730324.dat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}