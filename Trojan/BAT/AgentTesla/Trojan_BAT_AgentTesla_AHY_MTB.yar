
rule Trojan_BAT_AgentTesla_AHY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AHY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 0d 00 06 6f ?? ?? ?? 06 00 00 07 17 58 0b 07 20 a0 86 01 00 fe 04 0c 08 2d e7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}