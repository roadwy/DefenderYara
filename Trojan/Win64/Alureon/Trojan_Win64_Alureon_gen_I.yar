
rule Trojan_Win64_Alureon_gen_I{
	meta:
		description = "Trojan:Win64/Alureon.gen!I,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {81 3b 42 4b 46 53 74 07 b8 00 a0 00 c0 } //1
		$a_01_1 = {41 8b 01 25 ff ff ff 03 8d 0c 83 c1 f9 02 41 33 09 81 e1 ff ff ff 03 41 33 09 41 89 09 } //1
		$a_01_2 = {b8 0d 00 00 c0 41 23 c6 41 3b c6 0f 84 e3 00 00 00 48 8b 45 b8 33 c9 8b 50 14 c1 e2 09 ff 15 } //1
		$a_01_3 = {ff ca 41 0b d5 ff c2 0f b6 da 41 fe c0 8a 04 1c 41 80 e0 03 88 07 48 ff c7 49 ff cb 40 88 34 1c 75 c8 45 85 d2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}