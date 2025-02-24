
rule Trojan_Win64_LummaC_NZ_MTB{
	meta:
		description = "Trojan:Win64/LummaC.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_81_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 } //1 Go build ID: 
		$a_81_1 = {61 54 79 39 37 34 49 31 76 50 44 59 50 46 7a 6f 46 48 34 76 74 4a 4f 4e 72 4b 34 6f 52 44 76 6a 55 78 74 65 55 61 6e 37 62 65 45 } //2 aTy974I1vPDYPFzoFH4vtJONrK4oRDvjUxteUan7beE
		$a_81_2 = {44 72 52 4c 6e 6f 51 46 78 48 57 4a 35 6c 4a 55 6d 72 48 37 58 32 4c 30 78 65 55 75 36 53 55 53 39 35 44 63 36 31 65 57 32 59 63 } //2 DrRLnoQFxHWJ5lJUmrH7X2L0xeUu6SUS95Dc61eW2Yc
		$a_81_3 = {52 51 71 79 45 6f 67 78 35 4a 36 77 50 64 6f 78 71 4c 31 33 32 62 31 30 30 6a 38 4b 6a 63 56 48 4f 31 63 30 4b 4c 52 6f 49 68 63 } //2 RQqyEogx5J6wPdoxqL132b100j8KjcVHO1c0KLRoIhc
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2) >=7
 
}