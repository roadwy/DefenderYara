
rule Trojan_BAT_AgentTesla_ASDM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 8e 69 8d ?? 00 00 01 0b 16 0c 2b 1b 07 08 06 08 91 20 f2 52 00 00 28 ?? 03 00 06 28 ?? 00 00 0a 59 d2 9c 08 17 58 0c 08 06 8e 69 32 df } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}