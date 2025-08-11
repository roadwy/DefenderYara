
rule Trojan_Win32_LummaStealer_STG{
	meta:
		description = "Trojan:Win32/LummaStealer.STG,SIGNATURE_TYPE_PEHSTR_EXT,67 00 67 00 06 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //100
		$a_01_1 = {74 24 2e 88 54 24 2f 66 c7 44 24 30 00 00 8b 54 } //2
		$a_01_2 = {3d 8b 04 24 b9 13 00 80 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 } //1
		$a_01_3 = {d1 a0 75 ad 22 ab 52 37 67 50 13 8c e7 61 5a c5 } //1
		$a_01_4 = {ce 88 84 0c 7a 37 52 4d 41 4e 81 f9 ba c8 ad b2 } //1
		$a_01_5 = {45 00 57 69 6e 48 74 74 70 57 72 69 74 65 44 61 74 61 } //1 E楗䡮瑴坰楲整慄慴
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=103
 
}