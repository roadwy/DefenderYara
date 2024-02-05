
rule TrojanDownloader_BAT_AgentTesla_ERE_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ERE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 06 08 91 6f 90 01 03 0a 00 00 08 25 17 59 0c 16 fe 02 0d 09 90 00 } //01 00 
		$a_03_1 = {0b 12 01 23 00 00 00 00 00 00 34 40 28 90 01 03 0a 0a 06 90 00 } //01 00 
		$a_03_2 = {0b 06 07 16 07 8e 69 6f 90 01 03 0a 00 06 0c 90 09 0a 00 73 90 01 03 06 28 90 01 03 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}