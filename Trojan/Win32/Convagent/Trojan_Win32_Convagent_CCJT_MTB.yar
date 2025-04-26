
rule Trojan_Win32_Convagent_CCJT_MTB{
	meta:
		description = "Trojan:Win32/Convagent.CCJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 45 dc e1 32 41 00 89 75 e0 89 75 e4 89 45 e8 ff 15 } //2
		$a_01_1 = {8b 85 1c ff ff ff 05 3f 03 00 00 ff e0 } //1
		$a_01_2 = {b9 be f9 ff ff f7 d1 e8 00 00 00 00 5a 83 c2 11 92 bb 1b 84 44 1b 31 18 83 c0 04 e2 f9 4e 0f a8 } //1
		$a_01_3 = {17 90 f4 58 28 d2 0f 02 13 90 fa 64 90 2d e2 7d 54 03 f1 b6 73 a9 76 a6 ef 73 b6 30 8a 17 ec c1 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}