
rule Ransom_MSIL_FileCryptor_PP_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.PP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 72 00 65 00 61 00 64 00 5f 00 69 00 74 00 2e 00 74 00 78 00 74 00 } //1 \read_it.txt
		$a_01_1 = {41 00 6c 00 6c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 20 00 76 00 69 00 72 00 75 00 73 00 } //1 All your files have been encrypted with Ransomware virus
		$a_01_2 = {50 00 6f 00 6c 00 6c 00 79 00 48 00 6a 00 61 00 63 00 6b 00 69 00 6e 00 67 00 47 00 72 00 6f 00 75 00 70 00 } //1 PollyHjackingGroup
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}