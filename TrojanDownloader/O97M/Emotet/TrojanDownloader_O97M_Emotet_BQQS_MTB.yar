
rule TrojanDownloader_O97M_Emotet_BQQS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.BQQS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 46 20 3d 20 22 6d 73 68 74 61 20 68 74 74 70 90 02 03 2f 39 31 2e 32 90 02 02 2e 31 90 02 02 2e 31 90 02 02 2f 90 02 1e 68 68 2e 68 74 6d 6c 22 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}