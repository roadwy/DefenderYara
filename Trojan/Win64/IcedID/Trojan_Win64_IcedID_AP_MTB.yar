
rule Trojan_Win64_IcedID_AP_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0b 00 00 "
		
	strings :
		$a_01_0 = {6d 79 64 71 6d 42 62 76 2e 64 6c 6c } //10 mydqmBbv.dll
		$a_01_1 = {6e 74 75 67 6a 68 73 68 61 67 73 64 6d 61 6a 68 } //1 ntugjhshagsdmajh
		$a_01_2 = {47 45 5a 41 44 57 55 41 74 47 4d 61 64 72 47 73 } //1 GEZADWUAtGMadrGs
		$a_01_3 = {47 7a 49 4a 46 75 6e 56 } //1 GzIJFunV
		$a_01_4 = {73 6a 68 67 42 34 44 78 75 48 6b 78 4d 56 59 } //1 sjhgB4DxuHkxMVY
		$a_01_5 = {55 5a 59 68 59 57 66 4a } //1 UZYhYWfJ
		$a_01_6 = {74 62 32 71 4e 61 61 35 } //1 tb2qNaa5
		$a_01_7 = {66 57 69 4f 51 62 46 6b 37 } //1 fWiOQbFk7
		$a_01_8 = {6c 6b 43 38 78 6f 6f 71 5a 76 72 74 62 51 79 4a } //1 lkC8xooqZvrtbQyJ
		$a_01_9 = {6e 44 62 31 4d 38 70 54 43 6a } //1 nDb1M8pTCj
		$a_01_10 = {76 68 79 37 76 62 75 63 48 64 30 33 77 4a 38 } //1 vhy7vbucHd03wJ8
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=20
 
}