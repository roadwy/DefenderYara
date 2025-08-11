
rule Ransom_Win64_Prince_YAC_MTB{
	meta:
		description = "Ransom:Win64/Prince.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //1 stolen and encrypted
		$a_01_1 = {70 61 79 20 74 68 65 20 72 61 6e 73 6f 6d } //10 pay the ransom
		$a_01_2 = {77 61 6e 74 20 79 6f 75 72 20 6d 6f 6e 65 79 } //1 want your money
		$a_01_3 = {64 65 63 72 79 70 74 20 6f 6e 65 20 66 69 6c 65 } //1 decrypt one file
		$a_01_4 = {62 75 79 20 42 69 74 63 6f 69 6e } //1 buy Bitcoin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}