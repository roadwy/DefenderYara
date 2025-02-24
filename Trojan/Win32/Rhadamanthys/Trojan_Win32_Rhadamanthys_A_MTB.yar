
rule Trojan_Win32_Rhadamanthys_A_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {ff 95 e8 e5 ff ff } //1
		$a_02_1 = {f7 fb 89 74 24 20 db 44 24 20 d9 05 f8 ff 81 11 d9 c1 d8 c9 89 44 24 10 db 44 24 10 8b 84 24 ?? 00 00 00 de f9 d9 5c 24 6c d9 44 24 6c d9 80 f8 95 00 00 d9 c0 d8 35 fc ff 81 11 d9 05 e4 ff 81 11 d9 5c 24 5c d9 cb df f3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Rhadamanthys_A_MTB_2{
	meta:
		description = "Trojan:Win32/Rhadamanthys.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 da c1 e2 ?? 03 54 24 ?? 8d 3c 33 31 d7 89 da c1 ea ?? 01 ea 31 fa 29 d0 89 c2 c1 e2 ?? 03 14 24 8d 3c 06 31 d7 89 c2 c1 ea ?? 03 54 24 ?? 31 fa 29 d3 81 c6 } //2
		$a_03_1 = {89 c2 c1 e2 ?? 01 fa 89 fd 8d 3c 30 31 d7 89 c2 c1 ea ?? 03 54 24 ?? 31 fa 01 d3 89 da c1 e2 ?? 03 54 24 ?? 8d 3c 1e 31 d7 89 da c1 ea ?? 03 14 24 31 fa 89 ef 01 d0 81 c6 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}