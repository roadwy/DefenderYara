
rule TrojanDownloader_O97M_Quakbot_DAT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Quakbot.DAT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 67 61 72 6f 73 61 6e 2e 69 72 2f 78 75 6a 70 75 6f 6d 6b 61 6b 61 } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 67 61 72 6f 73 61 6e 2e 69 72 2f 78 75 6a 70 75 6f 6d 6b 61 6b 61 2f 35 33 30 33 34 30 2e 70 6e 67 } //01 00 
		$a_01_2 = {43 3a 5c 44 61 74 6f 70 5c } //01 00 
		$a_01_3 = {7a 69 70 66 6c 64 72 } //01 00 
		$a_01_4 = {4a 4a 43 43 43 4a } //00 00 
	condition:
		any of ($a_*)
 
}