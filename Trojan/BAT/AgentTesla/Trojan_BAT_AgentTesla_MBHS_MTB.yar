
rule Trojan_BAT_AgentTesla_MBHS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 07 08 11 07 91 11 04 61 09 11 06 91 61 28 ?? ?? ?? 0a 9c 11 06 1f 15 33 05 16 13 06 2b 06 11 06 17 58 13 06 11 07 17 58 13 07 11 07 08 8e 69 17 59 31 ca } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}