
rule Ransom_Win32_Phobos_A{
	meta:
		description = "Ransom:Win32/Phobos.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {57 33 c0 89 5d d4 8d 7d d8 ab ab 33 c0 89 5d c4 8d 7d c8 ab ab 33 c0 89 5d b8 8d 7d bc ab 8d b6 90 01 04 89 5d f0 89 5d f4 89 5d e0 ab 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Ransom_Win32_Phobos_A_2{
	meta:
		description = "Ransom:Win32/Phobos.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 96 3b 24 ee e6 1f 4c 43 6e 30 d5 5b 69 2b 9c f6 de 4a } //1
		$a_01_1 = {40 b5 d3 93 0e 11 c2 17 ab d7 29 37 40 e4 97 8f b0 7a 02 } //1
		$a_03_2 = {8d 7d e0 ab ab ab ab 8d 90 01 02 8d 90 01 02 50 8d 90 01 02 e8 90 01 04 ff 90 01 02 8b 90 01 01 ff 90 01 02 50 e8 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}