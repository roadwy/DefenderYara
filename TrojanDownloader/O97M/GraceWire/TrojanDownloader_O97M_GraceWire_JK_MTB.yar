
rule TrojanDownloader_O97M_GraceWire_JK_MTB{
	meta:
		description = "TrojanDownloader:O97M/GraceWire.JK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 72 65 71 75 65 73 74 62 69 6e 2e 6e 65 74 2f 72 2f 31 36 33 78 69 71 61 31 } //01 00 
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 22 22 28 6e 65 77 2d 6f 62 6a 65 63 74 20 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}