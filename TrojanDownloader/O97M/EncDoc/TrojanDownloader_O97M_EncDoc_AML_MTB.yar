
rule TrojanDownloader_O97M_EncDoc_AML_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.AML!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2f 22 2c 22 90 02 0f 70 3a 2f 2f 90 02 df 2e 90 02 df 2f 22 2c 22 90 02 df 70 3a 2f 2f 90 02 df 2e 90 02 df 2f 22 2c 22 90 02 df 70 3a 2f 2f 90 02 df 2e 90 02 df 2f 22 2c 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}