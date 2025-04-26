
rule TrojanDownloader_O97M_EncDoc_AML_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.AML!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2f 22 2c 22 [0-0f] 70 3a 2f 2f [0-df] 2e [0-df] 2f 22 2c 22 [0-df] 70 3a 2f 2f [0-df] 2e [0-df] 2f 22 2c 22 [0-df] 70 3a 2f 2f [0-df] 2e [0-df] 2f 22 2c 22 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}