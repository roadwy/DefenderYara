
rule TrojanDownloader_O97M_Quakbot_XL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Quakbot.XL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 72 61 6e 67 74 72 65 65 6d 2e 6e 65 74 2f 68 68 78 6a 78 2f 35 33 30 33 34 30 2e 70 6e 67 } //01 00  http://rangtreem.net/hhxjx/530340.png
		$a_01_1 = {68 74 74 70 3a 2f 2f 72 61 6e 67 74 72 65 65 6d 2e 6e 65 74 2f 68 68 78 6a 78 2f 44 6d } //01 00  http://rangtreem.net/hhxjx/Dm
		$a_01_2 = {7a 69 70 66 6c 64 72 } //01 00  zipfldr
		$a_01_3 = {43 3a 5c 49 6f 70 73 64 5c } //01 00  C:\Iopsd\
		$a_01_4 = {4a 4a 43 43 43 4a } //00 00  JJCCCJ
	condition:
		any of ($a_*)
 
}