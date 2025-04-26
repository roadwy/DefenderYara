
rule Trojan_BAT_AgentTesla_ABUV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABUV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {a2 13 04 d0 ?? 00 00 01 28 ?? ?? 00 0a 11 04 28 ?? ?? 00 0a 20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 07 6f ?? ?? 00 0a a2 28 ?? ?? 00 0a 74 ?? 00 00 01 13 05 11 05 6f ?? 01 00 0a 17 9a 7e ?? 00 00 04 13 06 11 06 } //4
		$a_01_1 = {47 61 6d 65 4f 66 4c 69 66 65 55 49 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 GameOfLifeUI.Properties.Resources.resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}