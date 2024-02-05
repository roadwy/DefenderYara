
rule TrojanDownloader_O97M_Trilark_A_dha{
	meta:
		description = "TrojanDownloader:O97M/Trilark.A!dha,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {73 68 65 6c 6c 90 02 03 28 74 65 78 74 62 6f 78 90 02 03 2e 74 65 78 74 20 2b 20 74 65 78 74 62 6f 78 90 02 03 2e 74 65 78 74 20 2b 20 74 65 78 74 62 6f 78 90 02 03 2e 74 65 78 74 90 00 } //01 00 
		$a_02_1 = {2e 74 65 78 74 20 2b 20 22 2e 22 20 2b 20 74 65 78 74 62 6f 78 90 02 03 2e 74 65 78 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}