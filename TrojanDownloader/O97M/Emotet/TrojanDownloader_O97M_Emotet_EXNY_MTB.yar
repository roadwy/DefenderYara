
rule TrojanDownloader_O97M_Emotet_EXNY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.EXNY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3a 2f 2f 39 31 2e 32 5e 34 30 2e 31 31 38 2e 31 5e 36 38 2f 90 02 06 2f 90 02 06 2f 90 02 01 73 90 02 01 65 2e 90 02 01 68 90 02 01 74 90 02 01 6d 90 02 01 6c 90 00 } //01 00 
		$a_03_1 = {3a 2f 2f 39 31 2e 32 5e 34 30 2e 31 31 38 2e 31 5e 36 38 2f 90 02 06 2f 90 02 06 2f 90 02 01 66 90 02 01 65 2e 90 02 01 68 90 02 01 74 90 02 01 6d 90 02 01 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}