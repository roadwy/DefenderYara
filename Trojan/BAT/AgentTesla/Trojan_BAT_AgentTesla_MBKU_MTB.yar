
rule Trojan_BAT_AgentTesla_MBKU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 07 07 8e 69 6a 5d d4 91 08 11 07 08 8e 69 6a 5d d4 91 61 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 59 20 00 01 00 00 58 13 08 07 11 07 07 8e 69 6a 5d d4 11 08 20 00 01 00 00 5d d2 9c 11 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}