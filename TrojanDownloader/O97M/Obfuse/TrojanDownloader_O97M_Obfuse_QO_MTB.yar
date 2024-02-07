
rule TrojanDownloader_O97M_Obfuse_QO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.QO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 74 6d 70 22 } //01 00  = "tmp"
		$a_01_1 = {3d 20 22 70 3a 2f 2f 31 22 } //01 00  = "p://1"
		$a_01_2 = {3d 20 22 6d 33 32 2e 65 78 22 } //01 00  = "m32.ex"
		$a_01_3 = {3d 20 22 38 31 2e 22 } //01 00  = "81."
		$a_01_4 = {3d 20 22 67 65 74 22 } //01 00  = "get"
		$a_01_5 = {3d 20 22 5c 7a 63 22 } //01 00  = "\zc"
		$a_01_6 = {3d 20 22 22 } //01 00  = ""
		$a_03_7 = {53 68 65 6c 6c 20 90 02 10 20 26 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}