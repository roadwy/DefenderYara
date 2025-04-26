
rule Trojan_Win64_Nekark_NIT_MTB{
	meta:
		description = "Trojan:Win64/Nekark.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4b 28 c7 44 24 50 01 00 10 00 ff 15 6e cf 0d 00 31 d2 48 8b 4b 28 ff 15 a2 cf 0d 00 3d 02 01 00 00 75 93 48 8b 4b 28 4c 89 e2 ff 15 56 ce 0d 00 48 8d 05 b7 fb ff ff 4c 89 e2 48 8b 4b 28 48 89 84 24 18 01 00 00 ff 15 12 cf 0d 00 0f b6 43 40 48 8b 35 27 24 0b 00 83 63 44 fe 83 e0 f0 48 8b 16 83 c8 05 88 43 40 48 85 d2 0f 84 54 01 00 00 48 83 7a 18 00 0f 84 39 01 00 00 48 8b 42 18 f0 83 00 01 48 8b 4b 30 48 85 c9 74 06 ff 15 b4 ce 0d 00 4c 89 e9 e8 04 ab ff ff 48 8b 4b 28 ff 15 7a ce 0d 00 e9 0d ff ff ff } //2
		$a_01_1 = {41 6e 64 20 67 6f 20 74 6f 75 63 68 20 73 6f 6d 65 20 67 72 61 73 73 } //1 And go touch some grass
		$a_01_2 = {53 74 6f 70 20 72 65 76 65 72 73 69 6e 67 20 74 68 65 20 70 72 6f 67 72 61 6d } //1 Stop reversing the program
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}