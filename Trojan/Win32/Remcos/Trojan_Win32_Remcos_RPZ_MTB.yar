
rule Trojan_Win32_Remcos_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 00 31 f1 81 c1 e6 00 00 00 eb 08 28 c8 91 21 28 c8 91 21 81 e9 e6 00 00 00 81 fa ?? ?? ?? ?? 75 08 ab 03 dc f7 ab ?? ?? ?? ?? 0c 10 81 fb ?? ?? ?? ?? 75 08 c0 f9 e4 6c c0 f9 e4 6c 81 fa } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}