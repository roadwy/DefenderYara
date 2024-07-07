
rule TrojanDownloader_O97M_EncDoc_IWDA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.IWDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3c 30 2c 20 90 02 08 2d 73 90 02 08 22 2c 30 2c 30 29 90 02 10 5c 61 64 77 2e 6f 63 78 90 02 10 5c 61 64 77 2e 6f 63 78 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}