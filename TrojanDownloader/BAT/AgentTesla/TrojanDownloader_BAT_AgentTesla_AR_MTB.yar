
rule TrojanDownloader_BAT_AgentTesla_AR_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {26 06 8e 69 1d 2d 09 90 0a 1d 00 72 73 90 01 02 70 28 0f 90 01 02 06 1a 2d 13 26 73 43 90 01 02 0a 1d 2d 0d 90 00 } //02 00 
		$a_03_1 = {07 06 08 91 6f 44 90 01 02 0a 08 25 17 59 0c 16 fe 02 0d 09 2d eb 90 00 } //01 00 
		$a_01_2 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_01_3 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}