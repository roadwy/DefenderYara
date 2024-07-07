
rule Ransom_MSIL_Filecoder_ET_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.ET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {47 72 65 61 74 20 6a 6f 62 2c 20 49 27 6d 20 64 65 63 72 79 70 74 69 6e 67 20 79 6f 75 72 20 66 69 6c 65 73 } //1 Great job, I'm decrypting your files
		$a_81_1 = {43 4c 4f 53 45 20 54 41 53 4b 20 4d 41 4e 41 47 45 52 20 4e 4f 57 21 } //1 CLOSE TASK MANAGER NOW!
		$a_81_2 = {45 78 74 65 6e 73 69 6f 6e 73 54 6f 45 6e 63 72 79 70 74 } //1 ExtensionsToEncrypt
		$a_81_3 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 @protonmail.com
		$a_81_4 = {44 45 43 52 59 50 54 20 41 4c 4c 20 46 49 4c 45 53 } //1 DECRYPT ALL FILES
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}