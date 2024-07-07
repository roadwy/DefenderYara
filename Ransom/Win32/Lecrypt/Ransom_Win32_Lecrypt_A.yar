
rule Ransom_Win32_Lecrypt_A{
	meta:
		description = "Ransom:Win32/Lecrypt.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 65 43 68 69 66 66 72 65 } //2 LeChiffre
		$a_01_1 = {70 68 70 3f 73 68 75 74 64 6f 77 6e 3d 26 72 65 61 73 6f 6e 3d } //1 php?shutdown=&reason=
		$a_01_2 = {69 6e 73 65 72 74 3d 26 73 65 72 76 65 72 6e 61 6d 65 3d } //1 insert=&servername=
		$a_01_3 = {2a 2e 2a 63 72 79 70 74 } //1 *.*crypt
		$a_01_4 = {3f 63 68 61 6e 67 65 63 6f 6d 6d 65 6e 74 3d 26 } //1 ?changecomment=&
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}