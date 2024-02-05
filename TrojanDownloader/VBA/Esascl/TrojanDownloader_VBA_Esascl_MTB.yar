
rule TrojanDownloader_VBA_Esascl_MTB{
	meta:
		description = "TrojanDownloader:VBA/Esascl!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 68 65 6c 6c 28 22 63 6d 64 2f 63 63 65 72 74 75 74 69 6c 2e 65 78 65 2d 75 72 6c 63 61 63 68 65 2d 73 70 6c 69 74 2d 66 } //01 00 
		$a_01_1 = {3a 2f 2f 61 73 73 69 73 74 61 6e 63 65 2d 65 73 70 61 63 65 2d 63 6c 69 65 6e 74 2e 63 6f 6d 2f 63 61 6c 63 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}