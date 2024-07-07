
rule Trojan_Win32_SmokeLdr_GE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLdr.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8d 0c 06 e8 90 01 04 30 01 46 3b f7 7c 90 0a 19 00 8b 44 24 90 00 } //10
		$a_02_1 = {3d 03 02 00 00 75 90 01 01 89 35 90 01 04 41 3b c8 90 0a 32 00 8b 15 90 01 04 8a 94 0a 90 01 04 8b 90 01 01 90 01 04 88 14 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}