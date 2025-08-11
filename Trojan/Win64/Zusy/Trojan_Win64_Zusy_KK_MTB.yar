
rule Trojan_Win64_Zusy_KK_MTB{
	meta:
		description = "Trojan:Win64/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {f3 43 0f 6f 04 08 0f 57 c2 f3 43 0f 7f 04 08 41 8d 42 f0 f3 42 0f 6f 04 08 66 0f 6f ca 0f 57 c8 f3 42 0f 7f 0c 08 41 8b c2 f3 42 0f 6f 04 08 0f 57 c2 f3 42 0f 7f 04 08 41 8d 42 10 f3 42 0f 6f 04 08 66 0f 6f ca 0f 57 c8 f3 42 0f 7f 0c 08 41 83 c0 40 41 83 c2 40 45 3b c3 } //6
		$a_01_1 = {41 8d 4a 01 45 8b ca 44 0f b6 04 19 42 0f b6 0c 13 41 80 e8 41 fe c9 49 d1 e9 c0 e1 04 41 83 c2 02 44 0a c1 45 88 04 01 8b 0f 44 3b d1 72 d1 } //10
		$a_01_2 = {54 75 6f 6e 69 41 67 65 6e 74 2e 64 6c 6c } //4 TuoniAgent.dll
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*10+(#a_01_2  & 1)*4) >=20
 
}