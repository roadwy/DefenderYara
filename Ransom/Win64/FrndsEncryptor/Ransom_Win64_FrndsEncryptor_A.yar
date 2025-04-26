
rule Ransom_Win64_FrndsEncryptor_A{
	meta:
		description = "Ransom:Win64/FrndsEncryptor.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {46 52 4e 44 53 3a 20 25 73 20 2f 70 61 74 68 2f 74 6f 2f 62 65 2f 65 6e 63 72 79 70 74 65 64 ?? 73 6c 69 63 65 20 62 6f 75 6e 64 } //1
		$a_03_1 = {4e 6f 72 6d 61 6c 20 46 69 6c 65 3a 20 25 73 ?? 45 52 52 4f 52 3a 20 25 64 20 21 3d 20 25 64 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}