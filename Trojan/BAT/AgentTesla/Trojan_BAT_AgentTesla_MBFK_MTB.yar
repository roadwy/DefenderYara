
rule Trojan_BAT_AgentTesla_MBFK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 11 1c 58 13 20 07 11 1e 91 13 21 11 21 08 11 1b 1f 16 5d 91 61 13 22 11 22 11 20 59 13 23 07 11 1e 11 23 11 1c 5d d2 9c 00 11 1b 17 58 13 1b 11 1b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}