
rule Ransom_Win64_Snatch_X_MTB{
	meta:
		description = "Ransom:Win64/Snatch.X!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 65 63 72 79 70 74 20 74 68 65 20 66 69 6c 65 73 20 6f 72 20 62 72 75 74 65 66 6f 72 63 65 20 74 68 65 20 6b 65 79 20 77 69 6c 6c 20 62 65 20 66 75 74 69 6c 65 20 61 6e 64 20 6c 65 61 64 20 74 6f 20 6c 6f 73 73 20 6f 66 20 74 69 6d 65 20 61 6e 64 20 70 72 65 63 69 6f 75 73 20 64 61 74 61 } //1 decrypt the files or bruteforce the key will be futile and lead to loss of time and precious data
		$a_01_1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_01_2 = {42 45 47 49 4e 20 52 53 41 20 50 55 42 4c 49 43 20 4b 45 59 } //1 BEGIN RSA PUBLIC KEY
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}