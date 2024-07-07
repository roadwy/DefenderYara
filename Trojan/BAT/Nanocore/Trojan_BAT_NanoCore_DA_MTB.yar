
rule Trojan_BAT_NanoCore_DA_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {52 48 4f 75 50 6d 66 47 4f 56 69 34 4c 47 37 4f 64 48 36 30 4a 57 79 46 56 6e 6d 75 4c 32 } //1 RHOuPmfGOVi4LG7OdH60JWyFVnmuL2
		$a_81_1 = {6d 4a 58 4c 30 58 6d 53 34 4f 33 66 4b 65 32 4f 70 4d 7a 6e 4d 63 6e 36 43 42 6d 66 46 63 48 36 31 63 55 58 4f 59 31 36 6b 4f 6d 66 74 5a 57 57 77 41 6d 50 46 63 32 61 34 63 57 58 4f 59 31 57 54 4b 32 } //1 mJXL0XmS4O3fKe2OpMznMcn6CBmfFcH61cUXOY16kOmftZWWwAmPFc2a4cWXOY1WTK2
		$a_81_2 = {4f 4c 45 4f 7a 4c 6d 66 54 57 47 7a 6d 47 47 66 4b 63 31 6d 70 4f 47 76 46 63 44 47 63 4c 6d 61 51 63 47 } //1 OLEOzLmfTWGzmGGfKc1mpOGvFcDGcLmaQcG
		$a_81_3 = {70 46 56 4c 45 5a 47 4f 70 49 32 33 46 4c 47 32 34 50 6c 33 6f 59 6e 69 76 4c 32 7a 66 55 32 57 77 4b 32 76 46 4c 46 6d 34 50 6b 62 4b 59 32 76 6d 65 7a 57 65 4c 6a 4c 6d 43 33 48 59 63 6d 65 } //1 pFVLEZGOpI23FLG24Pl3oYnivL2zfU2WwK2vFLFm4PkbKY2vmezWeLjLmC3HYcme
		$a_81_4 = {4a 65 33 4f 59 4d 6e 4c 48 65 48 69 34 4f 44 6e 4a 64 6d 69 34 4a 6e 54 47 4c 48 6d 77 4a 57 6e 4f 59 32 2b 75 50 67 3d 3d } //1 Je3OYMnLHeHi4ODnJdmi4JnTGLHmwJWnOY2+uPg==
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}