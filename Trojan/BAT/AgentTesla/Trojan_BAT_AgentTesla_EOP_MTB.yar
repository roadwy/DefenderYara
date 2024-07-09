
rule Trojan_BAT_AgentTesla_EOP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EOP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 07 09 e0 58 0b 07 1f 10 58 4b 07 1f 14 58 4b 13 04 07 09 e0 59 0b 8d ?? ?? ?? 01 0a 07 11 04 e0 58 0b 06 16 8f ?? ?? ?? 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}