
rule Trojan_Win64_LummaC_CZ_MTB{
	meta:
		description = "Trojan:Win64/LummaC.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {20 47 6f 20 62 75 69 6c 64 20 49 44 3a } //1  Go build ID:
		$a_01_1 = {76 34 49 4e 74 38 78 69 68 44 47 76 6e 72 66 6a 4d 44 56 58 47 78 77 39 77 72 66 78 59 79 43 6a 6b 30 4b 62 58 6a 68 52 35 35 73 } //2 v4INt8xihDGvnrfjMDVXGxw9wrfxYyCjk0KbXjhR55s
		$a_01_2 = {52 51 71 79 45 6f 67 78 35 4a 36 77 50 64 6f 78 71 4c 31 33 32 62 31 30 30 6a 38 4b 6a 63 56 48 4f 31 63 30 4b 4c 52 6f 49 68 63 } //2 RQqyEogx5J6wPdoxqL132b100j8KjcVHO1c0KLRoIhc
		$a_01_3 = {36 45 55 77 42 4c 51 2f 4d 63 72 31 45 59 4c 45 34 54 6e 31 56 64 57 31 41 34 63 6b 71 43 51 57 5a 42 77 38 48 72 30 6b 6a 70 51 } //2 6EUwBLQ/Mcr1EYLE4Tn1VdW1A4ckqCQWZBw8Hr0kjpQ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=7
 
}