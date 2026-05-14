
rule Trojan_Win32_Crysan_ARR_MTB{
	meta:
		description = "Trojan:Win32/Crysan.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c8 8d 04 3a 33 c8 2b d9 8b cb 8b c3 c1 e1 } //2
		$a_81_1 = {43 3a 5c 55 73 65 72 73 5c 74 61 6d 61 72 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 31 5c 52 65 6c 65 61 73 65 5c 43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 70 64 62 } //18 C:\Users\tamar\source\repos\ConsoleApplication1\Release\ConsoleApplication1.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*18) >=20
 
}