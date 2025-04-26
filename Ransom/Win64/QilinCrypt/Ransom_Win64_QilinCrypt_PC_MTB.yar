
rule Ransom_Win64_QilinCrypt_PC_MTB{
	meta:
		description = "Ransom:Win64/QilinCrypt.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 78 74 65 6e 73 69 6f 6e 3a 20 } //1 Extension: 
		$a_01_1 = {52 45 43 4f 56 45 52 2d 52 45 41 44 4d 45 2e 74 78 74 } //1 RECOVER-README.txt
		$a_01_2 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 2f 73 79 73 74 65 6d 20 77 61 73 20 65 6e 63 72 79 70 74 65 64 2e } //1 Your network/system was encrypted.
		$a_01_3 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin.exe delete shadows /all /quiet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}