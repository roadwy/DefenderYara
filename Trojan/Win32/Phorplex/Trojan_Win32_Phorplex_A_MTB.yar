
rule Trojan_Win32_Phorplex_A_MTB{
	meta:
		description = "Trojan:Win32/Phorplex.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 6b 58 6a 65 5a 6a 72 a2 90 01 04 58 6a 6e a2 90 01 04 58 6a 6c a2 90 01 04 58 6a 33 59 6a 32 88 0d 90 01 04 59 6a 2e 88 0d 90 01 04 59 6a 64 88 0d 90 01 04 59 6a 6b 5f 6a 72 66 89 3d 90 01 04 5f 6a 6e 66 89 3d 90 01 04 5f 6a 33 88 15 90 01 04 88 15 90 01 04 66 89 15 90 01 04 66 89 15 90 00 } //1
		$a_01_1 = {8a 4c 2a 03 8a d9 8a c1 80 e1 f0 c0 e0 06 0a 44 2a 02 80 e3 fc c0 e1 02 0a 0c 2a c0 e3 04 0a 5c 2a 01 83 c5 04 88 0c 3e 88 5c 3e 01 88 44 3e 02 83 c6 03 3b 6c 24 14 72 c1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}