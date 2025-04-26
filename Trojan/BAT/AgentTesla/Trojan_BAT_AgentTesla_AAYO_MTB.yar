
rule Trojan_BAT_AgentTesla_AAYO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAYO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 13 17 11 0b 17 58 13 1d 11 0b 20 00 40 01 00 5d 13 18 11 1d 20 00 40 01 00 5d 13 1e 11 15 11 1e 91 11 17 58 13 1f 11 15 11 18 91 13 20 11 20 11 1a 11 0b 1f 16 5d 91 61 13 21 11 21 11 1f 59 13 22 11 15 11 18 11 22 11 17 5d d2 9c 11 0b 17 58 13 0b 11 0b 20 00 40 01 00 fe 04 13 23 11 23 2d 9a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}