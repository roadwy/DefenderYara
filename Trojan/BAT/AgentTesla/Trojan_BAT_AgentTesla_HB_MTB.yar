
rule Trojan_BAT_AgentTesla_HB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {91 11 05 11 05 07 84 95 11 05 08 84 95 d7 6e 20 ?? ?? ?? ?? 6a 5f b7 95 61 86 9c 06 11 09 12 00 28 ?? ?? ?? ?? 2d 94 } //10
		$a_80_1 = {50 72 6f 70 65 72 5f 52 43 34 } //Proper_RC4  1
		$a_80_2 = {45 78 65 63 42 79 74 65 73 } //ExecBytes  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}
rule Trojan_BAT_AgentTesla_HB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.HB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 8e 69 d6 14 80 ?? ?? ?? 04 1d 5f 20 ?? ?? ?? ?? 80 ?? ?? ?? 04 62 d2 20 00 01 00 00 07 20 ?? ?? ?? ?? 80 ?? ?? ?? 04 8c ?? ?? ?? 01 80 ?? ?? ?? 04 11 05 80 ?? ?? ?? 04 14 80 ?? ?? ?? 04 14 80 ?? ?? ?? 04 5d 61 11 06 20 ?? ?? ?? ?? 80 ?? ?? ?? 04 80 ?? ?? ?? 04 b4 9c 07 17 20 ?? ?? ?? ?? 8c ?? ?? ?? 01 80 ?? ?? ?? 04 d6 0b 07 11 04 3e 66 ff ff ff } //10
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}