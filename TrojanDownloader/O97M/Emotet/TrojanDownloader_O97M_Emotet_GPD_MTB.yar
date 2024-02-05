
rule TrojanDownloader_O97M_Emotet_GPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.GPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 79 73 57 6f 77 36 34 90 02 08 5c 72 66 73 2e 64 6c 6c 90 02 06 57 69 6e 64 6f 77 73 90 02 1f 72 66 73 2e 64 6c 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}