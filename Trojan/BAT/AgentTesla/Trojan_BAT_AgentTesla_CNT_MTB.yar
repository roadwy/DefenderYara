
rule Trojan_BAT_AgentTesla_CNT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 1f 2c 6f ?? ?? ?? 0a 25 26 13 01 38 ?? ?? ?? 00 02 28 ?? ?? ?? 06 25 26 13 00 38 ?? ?? ?? ff } //5
		$a_01_1 = {48 48 47 67 36 35 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 HHGg65.g.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}