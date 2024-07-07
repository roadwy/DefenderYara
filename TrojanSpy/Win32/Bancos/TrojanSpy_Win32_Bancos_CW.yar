
rule TrojanSpy_Win32_Bancos_CW{
	meta:
		description = "TrojanSpy:Win32/Bancos.CW,SIGNATURE_TYPE_PEHSTR,20 00 20 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 77 61 72 65 5c 62 6f 72 6c 61 6e 64 5c 64 65 6c 70 68 69 5c 72 74 6c } //10 software\borland\delphi\rtl
		$a_01_1 = {45 6d 62 65 64 64 65 64 57 42 20 68 74 74 70 3a 2f 2f 62 73 61 6c 73 61 2e } //10 EmbeddedWB http://bsalsa.
		$a_01_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 69 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 62 00 61 00 6e 00 6b 00 69 00 6e 00 67 00 2e 00 63 00 61 00 69 00 78 00 61 00 2e 00 67 00 6f 00 76 00 2e 00 62 00 72 00 2f 00 53 00 49 00 49 00 42 00 43 00 2f 00 69 00 6e 00 64 00 65 00 78 00 } //1 https://internetbanking.caixa.gov.br/SIIBC/index
		$a_01_3 = {67 62 69 65 68 63 65 66 2e 64 6c 6c } //10 gbiehcef.dll
		$a_01_4 = {2e 58 43 6f 6d 70 } //1 .XComp
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1) >=32
 
}