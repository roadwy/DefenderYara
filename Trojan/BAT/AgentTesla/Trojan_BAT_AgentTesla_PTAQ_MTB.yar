
rule Trojan_BAT_AgentTesla_PTAQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7d 0a 00 00 04 06 28 ?? 00 00 0a 00 72 01 00 00 70 28 ?? 00 00 0a 00 28 ?? 00 00 0a 0b 07 2c 15 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}