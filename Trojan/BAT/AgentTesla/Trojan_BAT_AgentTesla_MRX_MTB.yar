
rule Trojan_BAT_AgentTesla_MRX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MRX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 06 72 df 11 00 70 6f 90 01 03 0a 74 90 01 03 01 28 90 01 03 06 72 90 01 03 70 72 90 01 03 70 6f 90 01 03 0a 17 8d 90 01 03 01 25 16 1f 2d 9d 6f 90 01 03 0a 0b 07 8e 69 8d 90 01 03 01 0c 16 13 06 2b 17 00 08 11 06 07 11 06 9a 1f 10 28 90 01 03 0a 9c 00 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 07 11 07 2d dc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}