
rule Trojan_Win64_IcedID_AO_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_01_0 = {42 45 6d 62 4e 4f 77 57 2e 64 6c 6c } //10 BEmbNOwW.dll
		$a_01_1 = {6e 74 75 67 6a 68 73 68 61 67 73 64 6d 61 6a 68 } //1 ntugjhshagsdmajh
		$a_01_2 = {41 4f 52 50 4d 67 31 33 68 46 62 } //1 AORPMg13hFb
		$a_01_3 = {47 45 5a 41 44 57 55 41 74 47 4d 61 64 72 47 73 } //1 GEZADWUAtGMadrGs
		$a_01_4 = {4c 68 70 58 35 53 51 44 39 30 57 78 } //1 LhpX5SQD90Wx
		$a_01_5 = {56 4f 61 46 73 59 38 50 4e } //1 VOaFsY8PN
		$a_01_6 = {6c 6b 43 38 78 6f 6f 71 5a 76 72 74 62 51 79 4a } //1 lkC8xooqZvrtbQyJ
		$a_01_7 = {6e 44 62 31 4d 38 70 54 43 6a } //1 nDb1M8pTCj
		$a_01_8 = {73 56 74 73 67 77 4a 79 42 36 31 78 6c 30 52 4f } //1 sVtsgwJyB61xl0RO
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=18
 
}