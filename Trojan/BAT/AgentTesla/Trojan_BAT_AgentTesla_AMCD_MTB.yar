
rule Trojan_BAT_AgentTesla_AMCD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0a 91 11 07 58 13 0b 07 11 09 91 13 0c 08 09 1f 16 5d 91 13 0d 11 0c 11 0d 61 13 0e 11 0e 11 0b 59 13 0f 07 11 09 11 0f 11 07 5d d2 9c 09 17 58 0d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}