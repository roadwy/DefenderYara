
rule Trojan_BAT_AgentTesla_BFE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {09 11 05 02 11 05 91 08 61 06 11 04 91 61 d2 9c 11 04 03 90 02 05 17 59 fe 01 13 06 11 06 2c 05 16 13 04 2b 06 11 04 17 58 13 04 00 11 05 17 58 13 05 11 05 07 17 59 fe 02 16 fe 01 13 07 11 07 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}