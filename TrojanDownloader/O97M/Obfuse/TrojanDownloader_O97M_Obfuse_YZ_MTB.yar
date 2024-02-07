
rule TrojanDownloader_O97M_Obfuse_YZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.YZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //01 00  Sub Auto_Open()
		$a_03_1 = {74 72 61 6e 73 76 61 6c 65 2e 73 73 6c 62 6c 69 6e 64 61 64 6f 2e 63 6f 6d 2f 90 02 09 2e 68 74 6d 6c 90 0a 27 00 68 74 74 70 3a 2f 2f 90 00 } //01 00 
		$a_03_2 = {53 68 65 6c 6c 20 28 90 02 09 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}