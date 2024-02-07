
rule TrojanDownloader_O97M_EncDoc_RS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {71 78 63 62 2e 6e 65 74 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 90 0a 3f 00 68 74 74 70 73 3a 2f 2f 90 00 } //01 00 
		$a_01_1 = {49 49 43 43 43 43 49 } //00 00  IICCCCI
	condition:
		any of ($a_*)
 
}