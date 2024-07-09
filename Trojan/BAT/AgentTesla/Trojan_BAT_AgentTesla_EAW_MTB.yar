
rule Trojan_BAT_AgentTesla_EAW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 16 13 04 2b 17 00 08 11 04 07 11 04 9a 1f 10 28 ?? 00 00 0a 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d dc } //2
		$a_01_1 = {4c 00 6f 00 67 00 69 00 63 00 47 00 61 00 6d 00 65 00 73 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 LogicGames.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}