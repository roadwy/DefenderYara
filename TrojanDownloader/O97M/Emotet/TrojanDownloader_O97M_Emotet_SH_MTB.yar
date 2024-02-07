
rule TrojanDownloader_O97M_Emotet_SH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 43 72 65 61 74 65 } //01 00  .Create
		$a_01_1 = {2b 20 28 22 53 54 41 52 54 55 22 29 } //01 00  + ("STARTU")
		$a_03_2 = {46 75 6e 63 74 69 6f 6e 90 02 14 28 29 90 0c 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 90 00 } //01 00 
		$a_03_3 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 90 0c 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 90 00 } //01 00 
		$a_03_4 = {4e 65 78 74 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_03_5 = {4e 65 78 74 90 01 02 43 72 65 61 74 65 4f 62 6a 65 63 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}