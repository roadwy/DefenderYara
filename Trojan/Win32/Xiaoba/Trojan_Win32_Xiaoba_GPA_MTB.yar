
rule Trojan_Win32_Xiaoba_GPA_MTB{
	meta:
		description = "Trojan:Win32/Xiaoba.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 01 00 00 00 68 02 42 40 00 68 02 42 40 00 8d 45 fc 50 ff 15 } //4
		$a_01_1 = {eb d3 c3 4d 44 35 b2 e9 bf b4 c6 f7 20 b2 e9 bf b4 cf c2 b3 cc d0 f2 4d 44 35 d3 d0 c4 be d3 d0 b8 c4 b1 e4 00 4d 44 35 a3 ba 00 35 44 4d } //4
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4) >=8
 
}