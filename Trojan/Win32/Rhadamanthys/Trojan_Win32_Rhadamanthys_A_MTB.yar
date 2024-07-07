
rule Trojan_Win32_Rhadamanthys_A_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 da c1 e2 90 01 01 03 54 24 90 01 01 8d 3c 33 31 d7 89 da c1 ea 90 01 01 01 ea 31 fa 29 d0 89 c2 c1 e2 90 01 01 03 14 24 8d 3c 06 31 d7 89 c2 c1 ea 90 01 01 03 54 24 90 01 01 31 fa 29 d3 81 c6 90 00 } //2
		$a_03_1 = {89 c2 c1 e2 90 01 01 01 fa 89 fd 8d 3c 30 31 d7 89 c2 c1 ea 90 01 01 03 54 24 90 01 01 31 fa 01 d3 89 da c1 e2 90 01 01 03 54 24 90 01 01 8d 3c 1e 31 d7 89 da c1 ea 90 01 01 03 14 24 31 fa 89 ef 01 d0 81 c6 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}