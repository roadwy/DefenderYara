
rule TrojanSpy_Win32_Banbra_AI{
	meta:
		description = "TrojanSpy:Win32/Banbra.AI,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {4e 00 20 00 4d 00 61 00 65 00 3a 00 20 00 } //1 N Mae: 
		$a_01_1 = {44 00 74 00 61 00 20 00 4e 00 61 00 73 00 63 00 3a 00 20 00 } //1 Dta Nasc: 
		$a_01_2 = {53 00 65 00 43 00 61 00 72 00 64 00 3a 00 20 00 } //1 SeCard: 
		$a_01_3 = {41 00 70 00 65 00 6c 00 69 00 64 00 6f 00 3a 00 20 00 } //1 Apelido: 
		$a_01_4 = {41 00 73 00 45 00 6c 00 6c 00 65 00 3a 00 20 00 } //1 AsElle: 
		$a_01_5 = {70 00 72 00 61 00 6b 00 65 00 69 00 6d 00 3d 00 } //1 prakeim=
		$a_01_6 = {20 00 2d 00 20 00 41 00 7a 00 75 00 6c 00 00 00 } //1
		$a_01_7 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6c 00 69 00 76 00 65 00 66 00 72 00 6f 00 6d 00 2e 00 67 00 65 00 2f 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 73 00 2f 00 6d 00 6f 00 64 00 5f 00 73 00 77 00 66 00 6f 00 62 00 6a 00 65 00 63 00 74 00 2f 00 65 00 6e 00 66 00 6f 00 2e 00 70 00 68 00 70 00 00 00 } //1
		$a_01_8 = {6d 00 69 00 63 00 61 00 20 00 46 00 65 00 64 00 65 00 72 00 61 00 6c 00 20 00 2d 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=8
 
}