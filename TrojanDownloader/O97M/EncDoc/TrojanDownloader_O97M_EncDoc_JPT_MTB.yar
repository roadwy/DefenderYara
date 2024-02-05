
rule TrojanDownloader_O97M_EncDoc_JPT_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.JPT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 77 77 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 73 2f 7a 68 70 31 62 30 36 69 6d 65 68 77 79 6c 71 2f 53 79 6e 61 70 74 69 63 73 2e 72 61 72 3f 64 6c 3d 31 } //00 00 
	condition:
		any of ($a_*)
 
}