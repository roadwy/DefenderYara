
rule Backdoor_BAT_DCRat_K_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 53 45 43 52 4d 4e 32 75 55 68 30 66 57 36 4d 65 48 2e 59 37 4f 52 35 44 4c 44 39 70 6f 4c 6c 52 34 61 78 77 } //2 jSECRMN2uUh0fW6MeH.Y7OR5DLD9poLlR4axw
		$a_01_1 = {47 78 56 37 51 6d 6f 65 49 43 46 32 6d 68 35 30 66 75 2e 46 50 36 45 38 4c 75 4f 59 68 31 75 52 44 76 4a 6e 67 } //2 GxV7QmoeICF2mh50fu.FP6E8LuOYh1uRDvJng
		$a_01_2 = {6d 76 70 62 4f 67 39 39 50 6a 4c 76 64 62 6e 6b 72 49 2e 63 4c 42 6a 6d 38 66 5a 4d 4d 69 6e 43 76 66 51 46 5a } //2 mvpbOg99PjLvdbnkrI.cLBjm8fZMMinCvfQFZ
		$a_01_3 = {44 00 61 00 72 00 6b 00 43 00 72 00 79 00 73 00 74 00 61 00 6c 00 20 00 52 00 41 00 54 00 } //2 DarkCrystal RAT
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}