
rule TrojanDropper_O97M_EncDoc_PN_MTB{
	meta:
		description = "TrojanDropper:O97M/EncDoc.PN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4a 4a 43 43 43 4a 4a } //1 JJCCCJJ
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_01_2 = {77 6d 69 63 2e 65 78 65 } //1 wmic.exe
		$a_03_3 = {70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 20 22 6d 73 68 74 61 2e 65 78 65 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-20] 2e 72 74 66 } //1
		$a_01_4 = {43 4f 56 49 44 2d 31 39 20 46 75 6e 65 72 61 6c 20 41 73 73 69 73 74 61 6e 63 65 20 48 65 6c 70 6c 69 6e 65 20 38 34 34 2d 36 38 34 2d 36 33 33 33 } //1 COVID-19 Funeral Assistance Helpline 844-684-6333
		$a_01_5 = {54 6f 20 6d 61 6b 65 20 61 20 66 6f 72 6d 20 76 69 73 69 62 6c 65 20 64 6f 20 6e 6f 74 20 66 6f 72 67 65 74 20 74 6f 20 63 6c 69 63 6b 20 65 6e 61 62 6c 65 20 63 6f 6e 74 65 6e 74 20 62 75 74 74 6f 6e 20 61 62 6f 76 65 } //1 To make a form visible do not forget to click enable content button above
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}