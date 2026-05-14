
rule Trojan_BAT_AgentTesla_AXSB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AXSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 09 0c 08 8e 69 8d ?? 00 00 01 13 04 16 0a 2b 14 11 04 06 08 06 91 11 05 28 ?? ?? 00 0a 59 d2 9c 06 17 58 0a 06 08 8e 69 32 e6 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}