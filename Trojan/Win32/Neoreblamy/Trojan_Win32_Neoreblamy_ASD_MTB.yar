
rule Trojan_Win32_Neoreblamy_ASD_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 43 6b 47 43 41 75 62 4e 4b 6a 64 64 42 56 49 74 75 6f 59 79 77 67 7a 41 } //1 pCkGCAubNKjddBVItuoYywgzA
		$a_01_1 = {77 69 6f 7a 6a 51 6a 59 53 6b 6e 64 5a 6e 71 76 69 64 75 74 41 43 53 50 7a 55 4b } //1 wiozjQjYSkndZnqvidutACSPzUK
		$a_01_2 = {75 73 62 6e 48 4c 63 50 62 42 49 6f 42 7a 6e 73 45 64 4a 55 51 61 7a 57 4b 76 71 6d 69 47 4f 73 75 4d 63 6a 55 68 72 61 65 } //1 usbnHLcPbBIoBznsEdJUQazWKvqmiGOsuMcjUhrae
		$a_01_3 = {53 58 4c 6d 48 50 46 61 45 6a 62 6d 6a 64 6e 77 4f 55 7a 57 43 59 49 64 62 73 58 45 70 69 } //1 SXLmHPFaEjbmjdnwOUzWCYIdbsXEpi
		$a_01_4 = {61 47 46 75 42 4f 53 77 6f 47 65 75 53 4e 6c 45 58 63 4e 50 56 6a 68 6e 53 41 66 } //1 aGFuBOSwoGeuSNlEXcNPVjhnSAf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}