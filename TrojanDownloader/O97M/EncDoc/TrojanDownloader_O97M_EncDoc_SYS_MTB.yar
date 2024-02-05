
rule TrojanDownloader_O97M_EncDoc_SYS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SYS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 65 62 6e 61 72 2e 69 6e 66 6f 2f 6d 73 67 62 6f 78 76 62 73 2e 68 74 6d 22 } //01 00 
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 57 69 6e 57 6f 72 64 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}