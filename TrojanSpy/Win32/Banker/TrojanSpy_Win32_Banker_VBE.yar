
rule TrojanSpy_Win32_Banker_VBE{
	meta:
		description = "TrojanSpy:Win32/Banker.VBE,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {55 73 65 72 2e 2e 2e 2e 2e 3a } //1 User.....:
		$a_01_1 = {50 77 64 2e 2e 2e 2e 2e 2e 2e 3a } //1 Pwd.......:
		$a_01_2 = {49 74 61 75 20 43 72 65 64 69 63 61 72 64 20 2d } //1 Itau Credicard -
		$a_01_3 = {40 67 6d 61 69 6c 2e 63 6f 6d } //1 @gmail.com
		$a_01_4 = {4d 41 49 4c 20 46 52 4f 4d 3a } //1 MAIL FROM:
		$a_01_5 = {41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 } //1 Arquivos de programas
		$a_01_6 = {44 65 6c 70 68 69 } //1 Delphi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}