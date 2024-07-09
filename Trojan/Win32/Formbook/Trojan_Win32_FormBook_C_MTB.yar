
rule Trojan_Win32_FormBook_C_MTB{
	meta:
		description = "Trojan:Win32/FormBook.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 e9 04 ba ?? ?? ?? ?? b8 ?? ?? ?? ?? 31 04 0f f7 da f8 11 d1 7d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_FormBook_C_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.C!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 e9 de d1 00 00 f7 d0 81 e3 a2 ae 00 00 43 05 65 1b 01 00 81 e3 be 3b 00 00 81 c3 8b 0a 01 00 5a 81 ea 6c 2c 00 00 81 e1 41 0c 00 00 81 c2 40 54 00 00 25 56 40 00 00 81 f1 e9 5b 00 00 48 81 ea c8 e5 00 00 3d c9 55 00 00 74 12 49 5a 81 e1 6b 04 01 00 59 81 f2 d9 10 00 00 c2 6a 4c } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}