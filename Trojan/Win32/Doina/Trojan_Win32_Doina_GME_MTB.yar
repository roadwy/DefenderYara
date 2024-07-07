
rule Trojan_Win32_Doina_GME_MTB{
	meta:
		description = "Trojan:Win32/Doina.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 56 18 8a 44 82 ff f7 ff 8a fc 8d 14 8a 3c 80 73 90 01 01 02 c0 eb 90 01 01 34 1b 41 88 02 3b 0e 90 00 } //10
		$a_03_1 = {57 8b f8 b8 90 01 04 48 46 08 9a c7 06 0a bf 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Doina_GME_MTB_2{
	meta:
		description = "Trojan:Win32/Doina.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {c1 f8 07 03 d0 5f 8b c2 5b 5d c3 8b c1 c1 e8 04 0f b7 1c 45 b0 c7 18 10 8d 3c 45 b2 c7 18 10 f6 c3 10 74 43 f6 c1 02 74 3e 8b c3 83 e0 0f 56 0f } //10
		$a_80_1 = {47 41 32 52 5a 4e 62 6d } //GA2RZNbm  1
		$a_01_2 = {74 34 53 56 68 30 62 } //1 t4SVh0b
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}