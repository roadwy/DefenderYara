
rule Trojan_Win32_LummaStealer_STH_{
	meta:
		description = "Trojan:Win32/LummaStealer.STH!!LummaStealer.STH,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 24 2e 88 54 24 2f 66 c7 44 24 30 00 00 8b 54 } //2
		$a_01_1 = {3d 8b 04 24 b9 13 00 80 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 } //1
		$a_01_2 = {d1 a0 75 ad 22 ab 52 37 67 50 13 8c e7 61 5a c5 } //1
		$a_01_3 = {ce 88 84 0c 7a 37 52 4d 41 4e 81 f9 ba c8 ad b2 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}