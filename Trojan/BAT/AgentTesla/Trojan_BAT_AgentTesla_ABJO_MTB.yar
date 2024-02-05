
rule Trojan_BAT_AgentTesla_ABJO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABJO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 11 05 07 8e 69 5d 07 11 05 07 8e 69 5d 91 08 11 05 1f 16 5d 91 61 28 90 01 03 0a 07 11 05 17 58 07 8e 69 5d 91 28 90 01 03 0a 59 20 90 01 03 00 58 20 90 01 03 00 5d d2 9c 11 05 15 58 13 05 11 05 16 2f bb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}