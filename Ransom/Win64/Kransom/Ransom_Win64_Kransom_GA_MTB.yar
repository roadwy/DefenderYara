
rule Ransom_Win64_Kransom_GA_MTB{
	meta:
		description = "Ransom:Win64/Kransom.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 31 aa 48 ff c1 48 83 ea 01 75 f4 } //2
		$a_01_1 = {49 20 62 65 6c 69 65 76 65 20 79 6f 75 27 76 65 20 65 6e 63 6f 75 6e 74 65 72 65 64 20 73 6f 6d 65 20 70 72 6f 62 6c 65 6d 73 } //1 I believe you've encountered some problems
		$a_01_2 = {5c 77 68 61 74 2e 74 78 74 } //1 \what.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}