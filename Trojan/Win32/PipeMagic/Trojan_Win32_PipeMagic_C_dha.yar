
rule Trojan_Win32_PipeMagic_C_dha{
	meta:
		description = "Trojan:Win32/PipeMagic.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 70 69 70 65 5c 6d 61 67 69 63 } //1 \\.\pipe\magic
		$a_01_1 = {5c 5c 2e 5c 70 69 70 65 5c 31 2e 25 73 } //1 \\.\pipe\1.%s
		$a_01_2 = {3a 00 66 00 75 00 63 00 6b 00 69 00 74 00 } //1 :fuckit
		$a_03_3 = {6a 04 8d 4d f0 e8 [0-10] 6a 04 8d 4d f0 e8 } //1
		$a_01_4 = {33 c9 89 4d d8 89 4d dc 89 4d e0 66 c7 45 e4 00 01 89 4d f8 3c 5a 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}