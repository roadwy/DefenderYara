
rule Trojan_Win64_Dordpmal_A{
	meta:
		description = "Trojan:Win64/Dordpmal.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 8b c8 b8 1f 85 eb 51 41 f7 e9 b8 93 24 49 92 c1 fa 05 44 8b c2 41 c1 e8 1f 41 03 d0 6b d2 64 } //2
		$a_01_1 = {48 8b ce 48 83 c9 0f 48 3b cf 77 44 48 8b d5 48 8b c7 48 d1 ea 48 2b c2 48 3b e8 77 33 48 8d 04 2a } //1
		$a_01_2 = {6c 69 62 6b 73 6a 67 6f 67 32 2e 64 6c 6c } //1 libksjgog2.dll
		$a_01_3 = {61 64 61 73 64 61 73 61 73 64 61 73 61 73 64 } //1 adasdasasdasasd
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}