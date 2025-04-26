
rule Trojan_Win32_PonyStealer_BD_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {35 8d b3 51 d1 32 7c 01 43 a2 cf 35 62 06 a5 b0 b8 4d d7 66 0e 35 77 57 38 41 3e 39 cc 7f } //2
		$a_01_1 = {4f d3 b3 30 3a 04 29 33 cf 97 87 a2 87 74 d6 24 91 82 b2 79 44 ba cd f5 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}