
rule Trojan_BAT_AgentTesla_NYU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 16 8c 03 00 00 01 a2 25 17 19 8d ?? ?? ?? 01 25 16 28 ?? ?? ?? 06 16 9a a2 25 17 } //5
		$a_01_1 = {50 69 72 61 74 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Pirates.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}