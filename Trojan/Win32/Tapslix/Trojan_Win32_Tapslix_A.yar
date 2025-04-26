
rule Trojan_Win32_Tapslix_A{
	meta:
		description = "Trojan:Win32/Tapslix.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 44 14 18 8a 14 19 32 d0 88 14 19 41 3b ce 7c e0 } //1
		$a_03_1 = {80 f9 23 74 10 8b 94 24 ?? ?? ?? ?? 40 3b c3 88 4c 10 0b 7c e4 } //1
		$a_03_2 = {56 57 c6 44 24 ?? 65 c6 44 24 ?? 78 c6 44 24 ?? 69 c6 44 24 ?? 74 c6 44 24 ?? 0d c6 44 24 ?? 0a } //1
		$a_01_3 = {6a 65 6a 78 6a 65 6a 2e 6a 64 6a 6d } //1 jejxjej.jdjm
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}