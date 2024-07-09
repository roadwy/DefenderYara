
rule Trojan_BAT_AgentTesla_ASDI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 38 ?? 00 00 00 07 08 06 08 91 72 ?? 01 00 70 28 ?? 00 00 0a 59 d2 9c 08 17 58 0c 08 06 8e 69 32 e4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}