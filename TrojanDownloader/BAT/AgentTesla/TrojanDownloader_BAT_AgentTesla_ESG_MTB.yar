
rule TrojanDownloader_BAT_AgentTesla_ESG_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ESG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0d 12 03 28 90 01 03 0a 23 00 00 00 00 00 00 34 40 fe 04 0c 08 90 09 08 00 00 00 06 6f 90 01 03 0a 90 00 } //0a 00 
		$a_03_1 = {0c 12 02 28 90 01 03 0a 1f 14 fe 04 0b 07 90 09 08 00 00 00 06 6f 90 01 03 0a 90 00 } //01 00 
		$a_03_2 = {06 07 03 07 91 6f 90 01 03 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 90 00 } //01 00 
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_4 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}