
rule Ransom_Win64_Filecoder_PAE_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.PAE!MTB,SIGNATURE_TYPE_PEHSTR,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 50 65 74 74 79 4c 61 77 20 31 2e 30 21 } //4 Your files are encrypted by PettyLaw 1.0!
		$a_01_1 = {45 4e 43 52 59 50 54 49 4f 4e 20 43 4f 4d 50 4c 45 54 45 } //2 ENCRYPTION COMPLETE
		$a_01_2 = {2e 70 65 74 74 79 } //2 .petty
		$a_01_3 = {43 68 65 63 6b 20 4d 61 74 72 69 78 20 72 6f 6f 6d 20 66 6f 72 20 64 65 63 72 79 70 74 69 6f 6e 20 69 6e 73 74 72 75 63 74 69 6f 6e 73 2e } //1 Check Matrix room for decryption instructions.
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=9
 
}