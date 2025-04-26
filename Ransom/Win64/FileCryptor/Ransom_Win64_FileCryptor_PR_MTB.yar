
rule Ransom_Win64_FileCryptor_PR_MTB{
	meta:
		description = "Ransom:Win64/FileCryptor.PR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 c8 49 8b c2 80 e1 07 c0 e1 03 48 d3 e8 43 30 04 08 49 ff c0 49 83 f8 ?? 72 } //1
		$a_01_1 = {5f 65 6e 63 72 79 70 74 5f 66 69 6c 65 } //1 _encrypt_file
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}