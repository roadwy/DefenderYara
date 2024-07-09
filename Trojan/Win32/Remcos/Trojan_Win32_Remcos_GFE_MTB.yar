
rule Trojan_Win32_Remcos_GFE_MTB{
	meta:
		description = "Trojan:Win32/Remcos.GFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {1b c0 40 33 c2 03 c1 0f b7 0d ?? ?? ?? ?? 03 c8 f7 d1 66 89 4d e8 8a c3 b1 5b f6 e9 a2 } //10
		$a_03_1 = {8a 45 d4 02 d0 8b 45 b4 8b 4d b8 34 ?? f6 ea 88 45 d5 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}