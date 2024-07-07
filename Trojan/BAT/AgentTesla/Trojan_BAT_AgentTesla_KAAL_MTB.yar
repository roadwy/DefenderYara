
rule Trojan_BAT_AgentTesla_KAAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KAAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 05 11 0b 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 11 04 11 0b 11 04 8e 69 5d 91 61 d2 81 90 01 01 00 00 01 00 11 0b 17 58 13 0b 11 0b 11 05 8e 69 fe 04 13 0f 11 0f 2d ca 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}