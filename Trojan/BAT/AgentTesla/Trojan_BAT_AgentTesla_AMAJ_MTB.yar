
rule Trojan_BAT_AgentTesla_AMAJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 25 4b 11 0c 11 0f 1f 0f 5f 95 61 54 11 0c 11 0f 1f 0f 5f 11 0c 11 0f 1f 0f 5f 95 11 05 25 1a 58 13 05 4b 61 20 ?? ?? ?? ?? 58 9e 11 0f 17 58 13 0f 11 16 17 58 13 16 11 16 11 06 37 c1 } //5
		$a_80_1 = {4e 4d 4b 4c 50 4f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //NMKLPO.Properties.Resources  1
	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_AMAJ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 03 17 8d ?? 00 00 01 25 16 09 20 ?? ?? 00 00 d6 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 17 d6 0d 09 08 31 d0 } //3
		$a_03_1 = {03 08 04 08 1f 09 5d 9a 28 ?? 00 00 0a 03 08 91 28 ?? 00 00 06 28 ?? 00 00 0a 9c 08 17 d6 0c 08 07 31 dd } //1
		$a_80_2 = {4c 6a 72 6f 72 61 72 6a 64 72 } //Ljrorarjdr  1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_80_2  & 1)*1) >=5
 
}