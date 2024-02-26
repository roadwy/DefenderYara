
rule TrojanDownloader_O97M_Qakbot_PUD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PUD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4a 4a 43 43 43 4a 4a } //01 00  JJCCCJJ
		$a_01_1 = {4a 4a 43 43 42 42 } //01 00  JJCCBB
		$a_01_2 = {7a 69 70 66 6c 64 72 } //01 00  zipfldr
		$a_03_3 = {68 74 74 70 73 3a 2f 2f 90 02 0f 2e 78 79 7a 2f 67 75 74 70 61 67 90 01 01 2e 70 68 70 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}