
rule TrojanDownloader_BAT_AgentTesla_EQE_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.EQE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 03 07 91 6f 90 01 03 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 2d e8 90 00 } //01 00 
		$a_03_1 = {11 04 11 08 16 11 09 6f 90 01 03 0a 00 00 11 06 11 08 16 11 07 6f 90 01 03 0a 25 13 09 16 fe 03 13 0a 11 0a 2d d9 90 00 } //01 00 
		$a_01_2 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //01 00 
		$a_01_3 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //00 00 
	condition:
		any of ($a_*)
 
}