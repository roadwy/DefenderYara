
rule Trojan_Win32_FormBook_KB{
	meta:
		description = "Trojan:Win32/FormBook.KB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {39 64 2f 4c 21 53 74 36 6a 37 57 28 41 2a 34 62 } //2 9d/L!St6j7W(A*4b
		$a_01_1 = {44 77 34 5e 69 2a 4d 33 38 6f 7e 43 47 29 } //2 Dw4^i*M38o~CG)
		$a_01_2 = {6a 4b 21 32 28 34 58 61 59 77 39 2a 40 37 44 66 } //2 jK!2(4XaYw9*@7Df
		$a_01_3 = {38 66 33 63 30 33 65 66 63 66 33 35 35 34 39 33 34 34 39 32 34 64 33 39 37 62 61 64 38 31 66 30 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 8f3c03efcf35549344924d397bad81f0.Resources.resources
		$a_01_4 = {24 34 35 65 62 38 61 65 32 2d 37 65 38 38 2d 34 33 63 33 2d 38 33 65 61 2d 33 66 30 30 63 39 32 37 64 38 38 63 } //1 $45eb8ae2-7e88-43c3-83ea-3f00c927d88c
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}