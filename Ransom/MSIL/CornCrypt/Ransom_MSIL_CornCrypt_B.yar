
rule Ransom_MSIL_CornCrypt_B{
	meta:
		description = "Ransom:MSIL/CornCrypt.B,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 65 73 74 6f 72 69 6e 67 20 79 6f 75 72 20 66 69 6c 65 73 20 2d 20 54 68 65 20 6e 61 73 74 79 20 77 61 79 } //1 Restoring your files - The nasty way
		$a_01_1 = {62 65 6c 6f 77 20 74 6f 20 6f 74 68 65 72 20 70 65 6f 70 6c 65 2c 20 69 66 20 74 77 6f 20 6f 72 20 6d 6f 72 65 20 70 65 6f 70 6c 65 20 77 69 6c 6c 20 69 6e 73 74 61 6c 6c 20 74 68 69 73 20 66 69 6c 65 20 61 6e 64 20 70 61 79 2c 20 77 65 20 77 69 6c 6c 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 20 66 6f 72 20 66 72 65 65 2e } //1 below to other people, if two or more people will install this file and pay, we will decrypt your files for free.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}