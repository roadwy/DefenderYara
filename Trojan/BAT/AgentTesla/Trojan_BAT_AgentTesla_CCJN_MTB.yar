
rule Trojan_BAT_AgentTesla_CCJN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CCJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 95 11 04 11 06 95 58 20 ?? ?? ?? ?? 5f 13 0b 11 09 11 0a 61 1f 2d 60 13 0c 11 09 1f 32 31 04 11 0c 13 09 11 0b 1f 7b 61 20 ?? ?? ?? ?? 5f 20 ?? ?? ?? ?? 58 20 ?? ?? ?? ?? 5e 26 09 11 07 07 11 07 91 11 04 11 0b 95 61 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}