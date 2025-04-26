
rule Trojan_Win32_SmokeLdr_GE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLdr.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8d 0c 06 e8 ?? ?? ?? ?? 30 01 46 3b f7 7c 90 0a 19 00 8b 44 24 } //10
		$a_02_1 = {3d 03 02 00 00 75 ?? 89 35 ?? ?? ?? ?? 41 3b c8 90 0a 32 00 8b 15 ?? ?? ?? ?? 8a 94 0a ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 88 14 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}