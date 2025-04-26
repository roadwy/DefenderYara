
rule TrojanSpy_Win32_Bancos_ADY{
	meta:
		description = "TrojanSpy:Win32/Bancos.ADY,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 74 6e 53 65 74 53 65 63 75 72 69 74 79 43 6c 69 63 6b } //10 btnSetSecurityClick
		$a_01_1 = {45 6e 74 65 72 20 74 68 65 6e 20 61 63 63 6f 75 6e 74 } //1 Enter then account
		$a_01_2 = {70 72 6f 67 72 61 6d 61 73 5c 41 6c 77 69 6c 20 53 6f 66 74 77 61 72 65 } //1 programas\Alwil Software
		$a_01_3 = {70 72 6f 67 72 61 6d 61 73 5c 41 56 47 5c 41 56 47 39 } //1 programas\AVG\AVG9
		$a_01_4 = {70 72 6f 67 72 61 6d 61 73 5c 4b 61 73 70 65 72 73 6b 79 20 4c 61 62 } //1 programas\Kaspersky Lab
		$a_01_5 = {70 72 6f 67 72 61 6d 61 73 5c 41 76 69 72 61 32 30 31 31 } //1 programas\Avira2011
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=12
 
}