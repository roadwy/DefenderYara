
rule Trojan_BAT_AgentTesla_AUN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AUN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {25 16 03 a2 14 14 90 01 0a 0c 08 14 02 90 01 0f 17 90 01 05 25 16 02 90 01 0a a2 14 14 90 01 0a 0d 09 90 01 05 14 90 01 05 17 90 01 05 25 16 90 01 05 a2 14 14 90 00 } //10
		$a_80_1 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  1
		$a_80_2 = {49 44 4d 2e 49 55 65 6c 70 6d 69 53 } //IDM.IUelpmiS  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}