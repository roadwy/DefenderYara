
rule Ransom_Win32_Bartcrypt_A{
	meta:
		description = "Ransom:Win32/Bartcrypt.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 65 63 6f 76 65 72 2e 74 78 74 00 } //2
		$a_01_1 = {5c 72 65 63 6f 76 65 72 2e 62 6d 70 00 } //2
		$a_01_2 = {2e 62 61 72 74 00 } //1 戮牡t
		$a_01_3 = {44 65 63 72 79 70 74 69 6e 67 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 69 73 20 6f 6e 6c 79 20 70 6f 73 73 69 62 6c 65 } //1 Decrypting of your files is only possible
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}