
rule Trojan_Win32_LummaC_GTZ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 14 ?? ?? ?? ?? 31 d1 89 4c 24 ?? 8b 4c 24 ?? 80 c1 ?? 88 8c 14 ?? ?? ?? ?? 42 81 fa } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_LummaC_GTZ_MTB_2{
	meta:
		description = "Trojan:Win32/LummaC.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {40 00 00 e0 2e 74 ?? 67 67 61 6e 74 00 40 00 00 00 20 44 00 00 22 00 } //10
		$a_80_1 = {64 65 66 4f 66 66 2e 65 78 65 } //defOff.exe  1
		$a_80_2 = {6f 66 66 44 65 66 2e 65 78 65 } //offDef.exe  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=11
 
}