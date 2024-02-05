
rule Trojan_BAT_AgentTesla_DAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 08 1f 41 59 1f 0a 58 d1 13 08 2b 08 11 08 1f 30 59 d1 13 08 09 11 06 1f 10 11 07 5a 11 08 58 d2 9c 00 11 06 17 58 13 06 11 06 08 fe 04 13 0b 11 0b 2d 84 } //02 00 
		$a_01_1 = {11 07 1f 41 59 1f 0a 58 d1 13 07 2b 08 11 07 1f 30 59 d1 13 07 07 19 11 06 5a 17 58 6f } //00 00 
	condition:
		any of ($a_*)
 
}