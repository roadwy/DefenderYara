
rule TrojanSpy_Win32_Banker_QW{
	meta:
		description = "TrojanSpy:Win32/Banker.QW,SIGNATURE_TYPE_PEHSTR_EXT,09 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c } //1 Software\Microsoft\Windows\CurrentVersion\explorer\Browser Helper Objects\
		$a_01_1 = {50 6f 72 20 66 61 76 6f 72 2c 20 70 72 65 65 6e 63 68 61 20 63 6f 72 72 65 74 61 6d 65 6e 74 65 20 6f 20 63 61 6d 70 6f 20 22 53 65 6e 68 61 20 45 6c 65 74 72 } //3 Por favor, preencha corretamente o campo "Senha Eletr
		$a_01_2 = {45 30 31 33 44 32 36 35 39 36 46 36 36 39 39 33 34 44 34 39 39 38 34 46 33 38 34 36 41 38 41 36 42 } //3 E013D26596F669934D49984F3846A8A6B
		$a_01_3 = {49 6d 61 67 65 33 43 6c 69 63 6b } //2 Image3Click
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=6
 
}