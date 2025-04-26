
rule TrojanDownloader_O97M_EncDoc_IWDA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.IWDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3c 30 2c 20 [0-08] 2d 73 [0-08] 22 2c 30 2c 30 29 [0-10] 5c 61 64 77 2e 6f 63 78 [0-10] 5c 61 64 77 2e 6f 63 78 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}