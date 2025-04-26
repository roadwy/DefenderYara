
rule Trojan_BAT_AgentTesla_AAYM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAYM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 36 06 08 5d 13 04 06 17 58 13 0a 07 11 04 91 13 0b 07 11 04 11 0b 11 06 06 1f 16 5d 91 61 07 11 0a 08 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 06 17 58 0a 06 08 11 07 17 58 5a fe 04 13 0c 11 0c 2d bb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}