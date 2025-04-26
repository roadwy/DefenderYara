
rule TrojanSpy_Win32_Bancos_XL{
	meta:
		description = "TrojanSpy:Win32/Bancos.XL,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 65 6e 68 61 2f 33 2e 2e 2e 2e 2e 3a } //4 Senha/3.....:
		$a_01_1 = {6e 6f 6d 65 20 64 6f 20 63 6f 72 6e 6f 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 3a } //3 nome do corno................:
		$a_01_2 = {45 6d 70 72 65 73 61 20 71 75 61 6e 64 6f 20 61 62 72 69 75 20 63 6f 6e 74 61 2e 2e 2e 3a } //4 Empresa quando abriu conta...:
		$a_01_3 = {45 73 74 61 64 6f 20 43 69 76 69 6c 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 3a } //3 Estado Civil.................:
		$a_01_4 = {74 75 64 6f 74 75 72 76 6f 54 69 6d 65 72 } //3 tudoturvoTimer
		$a_01_5 = {74 65 6d 70 6f 63 63 43 6c 69 63 6b } //3 tempoccClick
		$a_01_6 = {65 6d 70 72 65 41 43 6c 69 63 6b } //3 empreAClick
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*4+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3) >=23
 
}