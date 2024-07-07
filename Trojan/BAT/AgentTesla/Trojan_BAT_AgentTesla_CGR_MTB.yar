
rule Trojan_BAT_AgentTesla_CGR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 17 58 0b 07 20 00 01 00 00 5d 0b 09 11 07 07 94 58 0d 09 20 00 01 00 00 5d 0d 11 07 07 94 13 05 11 07 07 11 07 09 94 9e 11 07 09 11 05 9e 11 07 11 07 07 94 11 07 09 94 58 20 00 01 00 00 5d 94 13 04 11 08 08 11 09 08 91 11 04 61 d2 9c 08 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}