
rule TrojanDownloader_BAT_AgentTesla_ETJ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ETJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {07 25 17 59 0b 16 fe 02 0c 2b 03 00 2b f2 08 2d 02 2b 09 2b e0 6f 90 01 03 0a 2b e1 06 6f 90 01 03 0a 28 90 01 03 2b 0d 2b 00 09 2a 90 00 } //0a 00 
		$a_03_1 = {06 07 02 07 91 90 01 05 00 00 07 25 17 59 0b 16 fe 02 0c 08 2d e7 90 00 } //01 00 
		$a_01_2 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //01 00  SecurityProtocolType
		$a_01_3 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}