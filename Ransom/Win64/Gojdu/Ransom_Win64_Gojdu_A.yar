
rule Ransom_Win64_Gojdu_A{
	meta:
		description = "Ransom:Win64/Gojdu.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 00 } //1
		$a_01_1 = {3e 59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e } //1 >Your files have been encrypted.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}