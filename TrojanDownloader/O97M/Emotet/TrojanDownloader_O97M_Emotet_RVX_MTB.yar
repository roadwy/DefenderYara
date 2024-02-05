
rule TrojanDownloader_O97M_Emotet_RVX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RVX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 53 20 2e 2e 5c 90 02 05 33 2e 6f 6f 6f 63 63 63 78 78 78 90 00 } //01 00 
		$a_01_1 = {32 2e 6f 6f 6f 63 63 63 78 78 78 } //01 00 
		$a_01_2 = {31 2e 6f 6f 6f 63 63 63 78 78 78 } //00 00 
	condition:
		any of ($a_*)
 
}