
rule TrojanDownloader_O97M_EncDoc_ESM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ESM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 53 44 47 4f } //1 SSDGO
		$a_03_1 = {63 6d 64 20 2f 63 20 6d [0-01] 73 [0-01] 68 [0-01] 74 [0-01] 61 20 68 [0-01] 74 [0-01] 74 [0-01] 70 [0-01] 3a 2f [0-01] 2f 38 37 2e 32 35 31 2e 38 36 2e 31 37 38 2f [0-0f] 2f [0-0f] 2e 68 74 6d 6c } //3
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*3) >=4
 
}