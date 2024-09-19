
rule Trojan_BAT_RemLoader_CZ_MTB{
	meta:
		description = "Trojan:BAT/RemLoader.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_81_0 = {4d 41 4b 35 49 44 37 48 36 53 46 38 41 44 47 47 48 4a 46 4b 49 4c 4f 4f } //2 MAK5ID7H6SF8ADGGHJFKILOO
		$a_81_1 = {6d 69 6e 65 6c 61 62 66 6f 74 6f 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //2 minelabfoto.My.Resources
		$a_81_2 = {6e 63 6f 65 76 50 49 30 6a 67 49 78 39 6b 77 74 52 42 2e 39 67 56 43 55 46 32 4d 63 52 65 38 4f 43 41 52 75 73 } //2 ncoevPI0jgIx9kwtRB.9gVCUF2McRe8OCARus
		$a_81_3 = {31 43 34 42 46 44 44 39 2d 46 37 42 33 2d 34 46 34 32 2d 41 43 33 45 2d 44 43 31 43 41 45 30 39 38 34 41 36 } //1 1C4BFDD9-F7B3-4F42-AC3E-DC1CAE0984A6
		$a_81_4 = {6a 5a 39 54 6d 79 42 45 34 49 76 35 31 45 77 39 6a 77 } //1 jZ9TmyBE4Iv51Ew9jw
		$a_81_5 = {78 53 75 43 6e 49 46 6d 32 55 47 34 4c 54 76 42 79 49 } //1 xSuCnIFm2UG4LTvByI
		$a_81_6 = {58 55 52 36 71 6a 33 4e 75 42 61 5a 4b 5a 45 68 38 38 } //1 XUR6qj3NuBaZKZEh88
		$a_81_7 = {71 72 59 45 45 51 35 76 43 68 36 64 76 6b 4e 4e 33 6e 47 } //1 qrYEEQ5vCh6dvkNN3nG
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=11
 
}