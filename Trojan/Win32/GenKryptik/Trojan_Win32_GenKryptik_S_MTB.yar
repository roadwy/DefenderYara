
rule Trojan_Win32_GenKryptik_S_MTB{
	meta:
		description = "Trojan:Win32/GenKryptik.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8a d6 8a 4d 90 01 01 80 e2 90 01 01 80 e6 90 01 01 c0 e1 90 01 01 0a 4c 38 90 01 01 c0 e2 90 01 01 0a 14 38 c0 e6 90 01 01 0a 74 38 90 00 } //1
		$a_00_1 = {03 c7 d3 ea 03 55 c4 33 d0 33 d6 8b 75 d0 2b f2 89 75 d0 c1 e3 } //1
		$a_00_2 = {44 69 67 69 79 65 79 6f 20 64 6f 67 75 6c 61 77 6f 78 65 20 68 69 7a 6f } //1 Digiyeyo dogulawoxe hizo
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}