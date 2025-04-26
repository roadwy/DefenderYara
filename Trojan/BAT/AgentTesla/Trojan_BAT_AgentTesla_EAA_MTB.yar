
rule Trojan_BAT_AgentTesla_EAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {0c 16 13 05 2b 17 00 08 11 05 07 11 05 9a 1f 10 28 ?? 00 00 0a 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d dc } //3
		$a_01_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_2 = {53 70 6c 69 74 } //1 Split
		$a_01_3 = {72 00 61 00 64 00 61 00 72 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 radarsystem.Properties.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=7
 
}