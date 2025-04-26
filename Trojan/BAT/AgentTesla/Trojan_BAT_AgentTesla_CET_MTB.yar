
rule Trojan_BAT_AgentTesla_CET_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 02 18 d8 17 d6 11 00 8e 69 fe 04 13 03 38 ?? ?? ?? 00 00 00 11 02 17 d6 } //5
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 35 37 } //1 WindowsFormsApp57
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_CET_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5d 17 d6 28 ?? ?? ?? 0a da 13 04 07 11 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 09 17 d6 0d 09 90 09 0f 00 06 09 28 ?? ?? ?? 0a 08 09 08 6f ?? ?? ?? 0a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}