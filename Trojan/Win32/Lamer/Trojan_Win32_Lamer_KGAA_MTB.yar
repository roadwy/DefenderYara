
rule Trojan_Win32_Lamer_KGAA_MTB{
	meta:
		description = "Trojan:Win32/Lamer.KGAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {e8 ab b1 ff ff 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 ef 34 } //4
		$a_01_1 = {e8 ab b1 ff ff 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 c9 87 } //4
		$a_01_2 = {e8 ab b1 ff ff 80 c4 ef 80 ec ef 80 c4 ef 80 ec ef 80 c4 ef 80 ec ef 80 c4 ef 80 ec ef 80 c4 ef 80 ec ef 80 c4 ef 80 ec ef 80 c4 ef 80 ec ef 80 } //4
		$a_01_3 = {e8 ab b1 ff ff 66 81 f3 89 00 66 81 f3 89 00 66 81 f3 89 00 66 81 f3 89 00 66 81 f3 89 00 66 81 f3 89 00 66 81 f3 89 00 66 81 f3 89 00 66 81 f3 } //4
		$a_01_4 = {e8 ab b1 ff ff 89 c0 89 c0 89 c0 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 d2 86 } //4
		$a_01_5 = {2f 68 6f 6d 65 2f 7a 61 74 6f 2f 65 78 70 2f 00 76 69 73 75 61 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*1) >=5
 
}