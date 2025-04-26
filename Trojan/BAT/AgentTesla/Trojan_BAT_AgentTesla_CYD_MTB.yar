
rule Trojan_BAT_AgentTesla_CYD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 79 00 00 00 2b 0a 72 ?? ?? ?? 70 2b 0a 0b de 18 73 20 00 00 0a 2b ef 28 21 00 00 0a 2b ef 08 2c 06 08 6f 02 00 00 0a dc 07 28 ?? ?? ?? 2b 28 02 00 00 2b 28 24 00 00 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}