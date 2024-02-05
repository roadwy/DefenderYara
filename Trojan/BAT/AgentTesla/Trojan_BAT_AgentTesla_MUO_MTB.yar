
rule Trojan_BAT_AgentTesla_MUO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MUO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8e 69 6a 5d 28 90 01 04 28 90 01 04 91 06 07 06 8e 69 6a 5d 28 90 01 04 28 90 01 04 91 61 02 07 17 6a 58 02 8e 69 6a 5d 28 90 01 04 28 90 01 04 91 59 6a 20 00 01 00 00 6a 58 20 00 01 00 00 6a 5d d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}