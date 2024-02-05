
rule TrojanDownloader_O97M_Qakbot_ALA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.ALA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 34 36 38 36 2e 34 38 30 32 39 37 38 30 30 39 2e 64 61 74 } //01 00 
		$a_01_1 = {2e 4f 4f 4f 43 43 43 58 58 58 } //01 00 
		$a_01_2 = {44 69 72 65 63 74 6f 72 79 41 } //01 00 
		$a_03_3 = {75 52 6c 4d 6f 6e 90 02 2f 72 33 32 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}