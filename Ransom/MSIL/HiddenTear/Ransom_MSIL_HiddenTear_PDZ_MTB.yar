
rule Ransom_MSIL_HiddenTear_PDZ_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.PDZ!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //3 Your files have been encrypted
		$a_01_1 = {41 6e 79 20 61 74 74 65 6d 70 74 73 20 74 6f 20 64 65 63 72 79 70 74 20 61 20 66 69 6c 65 20 77 69 74 68 6f 75 74 20 70 65 72 6d 69 73 73 69 6f 6e 20 77 69 6c 6c 20 72 65 73 75 6c 74 20 69 6e 20 69 74 73 20 64 65 6c 65 74 69 6f 6e } //3 Any attempts to decrypt a file without permission will result in its deletion
		$a_01_2 = {72 61 6e 73 6f 6d 20 70 61 79 6d 65 6e 74 } //2 ransom payment
		$a_01_3 = {46 00 69 00 6c 00 65 00 4b 00 72 00 79 00 70 00 74 00 65 00 72 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 46 00 49 00 6c 00 65 00 7c 00 2a 00 2e 00 66 00 69 00 6c 00 65 00 6b 00 72 00 79 00 70 00 74 00 65 00 72 00 7c 00 41 00 6c 00 6c 00 20 00 46 00 69 00 6c 00 65 00 73 00 7c 00 2a 00 2e 00 2a 00 } //2 FileKrypter Encrypted FIle|*.filekrypter|All Files|*.*
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=10
 
}