
rule TrojanDownloader_O97M_Emotet_CPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.CPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 65 67 73 76 72 33 32 2e 65 78 65 90 02 0f 53 79 73 57 6f 77 36 34 90 02 06 57 69 6e 64 6f 77 73 90 02 40 5c 66 62 64 2e 64 6c 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}