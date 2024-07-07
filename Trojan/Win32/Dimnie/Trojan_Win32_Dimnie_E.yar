
rule Trojan_Win32_Dimnie_E{
	meta:
		description = "Trojan:Win32/Dimnie.E,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 "
		
	strings :
		$a_01_0 = {0f b6 d0 c1 e2 18 89 14 31 8a d0 80 e2 80 83 c1 04 f6 da 1a d2 80 e2 1b 02 c0 32 c2 83 f9 28 7c d9 } //8
		$a_01_1 = {81 e1 ff 01 00 00 5f 3d cd ab cd ab 75 05 b8 48 00 00 00 0f } //2
		$a_01_2 = {62 61 62 62 61 62 62 61 62 2e 72 75 } //2 babbabbab.ru
		$a_01_3 = {62 61 62 66 61 62 62 61 62 2e 75 61 } //2 babfabbab.ua
		$a_01_4 = {62 61 62 66 61 62 62 61 62 2e 70 77 } //2 babfabbab.pw
		$a_01_5 = {6d 65 6e 74 69 6f 6e 65 64 20 4d 69 6c 6c 69 6f 6e 20 73 63 68 6f 6f 6c 77 6f 72 6b } //1 mentioned Million schoolwork
		$a_01_6 = {73 79 73 61 64 6d 69 6e 20 43 75 72 6c 79 20 74 72 61 76 65 6c 20 4c 75 63 61 73 } //1 sysadmin Curly travel Lucas
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=12
 
}