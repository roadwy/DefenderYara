
rule TrojanDownloader_BAT_AgentTesla_ERJ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ERJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 07 06 08 91 6f 90 01 03 0a 00 00 08 25 17 59 0c 16 fe 02 0d 09 90 00 } //01 00 
		$a_03_1 = {20 00 0c 00 00 28 90 01 03 0a 00 00 de 05 26 00 00 de 00 73 90 01 03 0a 03 73 90 01 03 0a 28 90 01 03 0a 0a 2b 00 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}