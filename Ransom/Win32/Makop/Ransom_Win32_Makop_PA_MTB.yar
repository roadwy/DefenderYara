
rule Ransom_Win32_Makop_PA_MTB{
	meta:
		description = "Ransom:Win32/Makop.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 10 03 44 24 38 8b cd 89 44 24 10 8b 44 24 1c 03 c5 c1 e9 05 03 4c 24 2c 89 44 24 20 89 3d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 8b 44 24 20 31 44 24 10 81 3d ?? ?? ?? ?? 72 07 00 00 75 } //1
		$a_02_1 = {33 4c 24 10 89 7c 24 14 2b f1 89 74 24 18 81 f3 07 eb dd 13 81 6c 24 14 52 ef 6f 62 b8 41 e5 64 03 81 6c 24 14 68 19 2a 14 81 44 24 14 be 08 9a 76 8b 4c 24 14 8b c6 d3 e0 03 44 24 30 81 3d ?? ?? ?? ?? 1a 0c 00 00 89 44 24 10 75 } //10
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*10) >=11
 
}