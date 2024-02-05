
rule TrojanDownloader_BAT_AgentTesla_ERG_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ERG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 06 08 91 6f 90 01 03 0a 00 00 08 25 17 59 0c 16 fe 02 0d 09 90 00 } //01 00 
		$a_03_1 = {13 05 12 05 23 00 00 00 00 00 00 24 40 28 90 01 03 0a 0b 28 90 01 03 0a 13 05 12 05 23 00 00 00 00 00 00 24 40 28 90 01 03 0a 0b 90 00 } //01 00 
		$a_03_2 = {0a 0c 08 6f 90 01 03 0a 6f 90 01 03 0a 0d 09 06 6f 90 01 03 0a 00 06 6f 90 01 03 0a 90 09 09 00 73 90 01 03 0a 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}