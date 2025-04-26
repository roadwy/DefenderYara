
rule Trojan_BAT_AgentTesla_AMBZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 11 15 58 13 19 07 11 17 91 13 1a 11 1a 08 11 14 1f 16 5d 91 61 13 1b 11 1b 11 19 59 13 1c 07 11 17 11 1c 11 15 5d d2 9c 00 11 14 17 58 13 14 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}