
rule Trojan_Win32_Pazzky_A{
	meta:
		description = "Trojan:Win32/Pazzky.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {2e 70 68 70 3f 70 61 7a 7a 3d 74 61 7a 6d 61 6e 69 61 6b 61 73 70 61 72 73 6b 79 66 72 6f 6d 77 68 65 72 65 26 26 69 64 3d } //5 .php?pazz=tazmaniakasparskyfromwhere&&id=
		$a_01_1 = {3a 5c 43 6f 6c 64 70 6c 61 79 5c 56 69 76 61 20 6c 61 20 76 69 64 61 2e 65 78 65 00 } //1
		$a_01_2 = {77 69 6e 64 6f 77 73 6c 6f 67 6e 2e 65 78 65 00 } //1
		$a_01_3 = {6c 6f 63 61 6c 68 6f 73 74 2f 6b 61 73 70 61 72 73 6b 79 2f } //1 localhost/kasparsky/
		$a_01_4 = {26 26 4c 6f 63 61 6c 69 73 61 74 69 6f 6e 5f 67 65 6f 67 72 61 70 68 69 71 75 65 3d 00 } //1
		$a_01_5 = {41 6e 74 ef 76 69 72 2e 65 78 65 00 } //1
		$a_01_6 = {26 26 55 72 6c 5f 69 6d 61 67 65 5f 64 72 61 70 65 61 75 3d 00 } //1
		$a_01_7 = {26 26 41 64 72 65 73 73 65 5f 49 70 3d 00 } //1 ☦摁敲獳彥灉=
		$a_01_8 = {69 70 6c 6f 63 61 74 69 6f 6e 74 6f 6f 6c 73 2e 63 6f 6d 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}