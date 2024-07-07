
rule Trojan_BAT_AgentTesla_AMCE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 08 07 11 08 91 11 06 58 13 09 07 11 07 91 08 09 1f 16 5d 91 13 0a 11 0a 61 11 09 59 13 0b 07 11 07 11 0b 11 06 5d d2 9c 09 17 58 0d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}