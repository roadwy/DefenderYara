
rule TrojanDownloader_BAT_AgentTesla_D_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 00 0c 00 00 28 90 01 03 0a 90 01 01 28 90 01 03 06 0a 06 6f 90 01 03 0a 74 90 01 03 01 0b 2b 00 07 2a 90 00 } //01 00 
		$a_03_1 = {72 01 00 00 70 73 90 01 03 0a 28 90 01 03 0a 74 90 01 03 01 0a 2b 00 06 2a 90 00 } //01 00 
		$a_03_2 = {0a 00 06 6f 90 01 03 0a 80 90 01 03 04 00 de 90 0a 21 00 0a 00 28 90 01 03 06 6f 90 01 03 0a 06 6f 90 00 } //01 00 
		$a_03_3 = {59 d2 9c 00 06 17 58 0a 06 7e 90 01 03 04 8e 69 fe 90 01 01 0b 07 2d 90 0a 28 00 7e 90 01 03 04 06 7e 90 01 03 04 06 91 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}