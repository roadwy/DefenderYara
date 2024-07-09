
rule Trojan_BAT_AgentTesla_ENW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 61 06 09 91 61 1e 2c d8 } //1
		$a_03_1 = {02 08 23 00 00 00 00 00 00 10 40 28 ?? ?? ?? 0a b7 6f ?? ?? ?? 0a 23 00 00 00 00 00 00 70 40 28 ?? ?? ?? 0a b7 28 ?? ?? ?? 0a 84 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}