
rule Trojan_Win32_LokiBot_GA_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f8 8a 80 [0-20] 34 e9 8b 55 ?? 03 55 ?? 88 02 [0-20] 8b 45 ?? 8a 80 [0-20] 8b 55 ?? 03 55 ?? 88 02 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LokiBot_GA_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {71 00 64 00 71 00 66 00 51 00 77 00 30 00 63 00 38 00 77 00 48 00 65 00 54 00 56 00 48 00 51 00 70 00 72 00 64 00 76 00 61 00 63 00 35 00 46 00 7a 00 76 00 4b 00 39 00 32 00 4c 00 6a 00 46 00 34 00 30 00 } //1 qdqfQw0c8wHeTVHQprdvac5FzvK92LjF40
		$a_01_1 = {44 00 46 00 4c 00 36 00 49 00 47 00 67 00 61 00 54 00 39 00 37 00 62 00 77 00 41 00 31 00 5a 00 4a 00 61 00 51 00 35 00 5a 00 35 00 67 00 78 00 4f 00 32 00 30 00 33 00 } //1 DFL6IGgaT97bwA1ZJaQ5Z5gxO203
		$a_01_2 = {49 00 6e 00 64 00 73 00 6b 00 72 00 69 00 76 00 6e 00 69 00 6e 00 67 00 73 00 61 00 72 00 62 00 65 00 6a 00 64 00 65 00 73 00 } //1 Indskrivningsarbejdes
		$a_01_3 = {46 00 6f 00 72 00 65 00 73 00 70 00 72 00 67 00 73 00 65 00 6c 00 73 00 74 00 69 00 64 00 73 00 70 00 75 00 6e 00 6b 00 74 00 65 00 74 00 38 00 } //1 Foresprgselstidspunktet8
		$a_01_4 = {4b 00 75 00 6e 00 73 00 74 00 6e 00 65 00 72 00 70 00 72 00 6f 00 62 00 6c 00 65 00 6d 00 61 00 74 00 69 00 6b 00 73 00 39 00 } //1 Kunstnerproblematiks9
		$a_01_5 = {6a 00 5a 00 35 00 67 00 77 00 4f 00 74 00 4c 00 6a 00 51 00 6b 00 44 00 36 00 30 00 } //1 jZ5gwOtLjQkD60
		$a_01_6 = {69 00 41 00 43 00 30 00 4d 00 6b 00 33 00 56 00 43 00 6c 00 48 00 63 00 6d 00 76 00 64 00 56 00 45 00 76 00 4e 00 79 00 56 00 42 00 31 00 32 00 } //1 iAC0Mk3VClHcmvdVEvNyVB12
		$a_00_7 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}