
rule Trojan_Win32_SmokeLdr_GA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLdr.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {30 04 33 83 7d ?? ?? 90 18 46 3b 75 ?? ?? ?? 81 7d ?? 71 11 00 00 5f 5e } //10
		$a_02_1 = {88 14 0f 3d 03 02 00 00 75 ?? 89 35 ?? ?? ?? ?? 41 3b c8 72 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}