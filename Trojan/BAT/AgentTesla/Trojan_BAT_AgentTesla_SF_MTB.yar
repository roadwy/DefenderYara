
rule Trojan_BAT_AgentTesla_SF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 18 5a 18 6f fa 00 00 0a 1f 10 28 fb 00 00 0a 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d dc } //2
		$a_81_1 = {4e 61 6b 6c 69 79 65 2e 41 6e 61 73 61 79 66 61 2e 72 65 73 6f 75 72 63 65 73 } //2 Nakliye.Anasayfa.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AgentTesla_SF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {11 04 18 6f ?? ?? ?? 0a ?? ?? ?? ?? ?? 28 ?? ?? ?? 0a 04 07 6f ?? ?? ?? 0a ?? ?? ?? ?? ?? 6a 61 b7 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 05 08 11 05 6f ?? ?? ?? 0a 26 07 04 ?? ?? ?? ?? ?? 17 da 33 } //10
		$a_80_1 = {58 4f 52 5f 44 65 63 72 79 70 74 } //XOR_Decrypt  1
		$a_80_2 = {73 61 64 61 64 61 } //sadada  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}