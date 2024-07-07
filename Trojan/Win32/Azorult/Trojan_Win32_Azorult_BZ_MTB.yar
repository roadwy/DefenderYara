
rule Trojan_Win32_Azorult_BZ_MTB{
	meta:
		description = "Trojan:Win32/Azorult.BZ!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 45 c8 70 72 6c 20 c7 45 cc 68 79 70 65 c7 45 d0 72 76 20 20 e9 } //1
		$a_01_1 = {c7 45 d4 58 65 6e 56 c7 45 d8 4d 4d 58 65 } //1
		$a_01_2 = {8b ce c1 e1 05 8b fe c1 ef 02 03 cf 0f be 3a 03 cf 33 f1 42 48 e9 38 26 00 00 } //1
		$a_01_3 = {56 8b f1 85 f6 0f 84 1e 00 00 00 33 c9 41 2b c8 57 8b 7c 24 0c 8d 14 01 83 e2 0f 8a 14 3a 30 10 40 4e 0f 85 e9 ff ff ff 5f 5e c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}