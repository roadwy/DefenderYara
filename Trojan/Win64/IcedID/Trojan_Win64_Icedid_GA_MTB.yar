
rule Trojan_Win64_Icedid_GA_MTB{
	meta:
		description = "Trojan:Win64/Icedid.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 02 c7 44 24 ?? ?? ?? ?? ?? 48 8b 54 24 ?? 48 81 c2 01 00 00 00 48 89 54 24 ?? c7 44 24 58 ?? ?? ?? ?? 8b 4c 24 ?? 81 e9 a1 16 9f 6e 83 c1 ff 81 c1 a1 16 9f 6e 89 4c 24 ?? 83 f9 00 0f 84 ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? e9 } //10
		$a_80_1 = {50 6c 75 67 69 6e 49 6e 69 74 } //PluginInit  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}