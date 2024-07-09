
rule Trojan_Win32_SmokeLdr_GF_MTB{
	meta:
		description = "Trojan:Win32/SmokeLdr.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 08 8d 0c 06 e8 ?? ?? ?? ?? 30 01 46 3b f7 } //10
		$a_02_1 = {3d 03 02 00 00 75 [0-09] 41 3b c8 90 0a 32 00 8b 15 ?? ?? ?? ?? 8a 94 0a ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 88 14 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}