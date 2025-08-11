
rule Trojan_Win32_Tedy_LMD_MTB{
	meta:
		description = "Trojan:Win32/Tedy.LMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 14 31 8a c3 32 c2 8a d0 80 e2 0f c0 e2 04 c0 e8 04 02 d0 88 14 31 49 } //15
		$a_01_1 = {8b 4d 0a 8d 7a 12 89 4a 0a 8b 44 24 10 89 42 0e 8b 4c 24 10 8b d1 8b f3 c1 e9 02 f3 a5 8b ca b8 01 00 00 00 83 e1 03 f3 a4 5f 5e 5d 5b 81 c4 14 01 00 00 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}