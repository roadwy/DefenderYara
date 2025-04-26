
rule TrojanSpy_Win32_Bancos_ALP{
	meta:
		description = "TrojanSpy:Win32/Bancos.ALP,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_01_0 = {2e 63 61 69 78 61 2e 67 6f 76 2e 62 72 2f 53 49 49 42 43 2f 69 6e 64 65 78 2e 70 72 6f 63 65 73 73 61 } //1 .caixa.gov.br/SIIBC/index.processa
		$a_01_1 = {2e 6c 69 76 65 2e 63 6f 6d 2f 6c 6f 67 69 6e } //1 .live.com/login
		$a_01_2 = {2e 62 62 2e 63 6f 6d 2e 62 72 2f 61 61 70 6a 2f 6c 6f 67 69 6e 70 66 65 2e 62 62 } //1 .bb.com.br/aapj/loginpfe.bb
		$a_01_3 = {63 69 74 69 62 61 6e 6b 2e 63 6f 6d 2e 62 72 } //1 citibank.com.br
		$a_01_4 = {62 61 6e 63 6f 62 72 61 73 69 6c 2e 63 6f 6d 2e 62 72 } //1 bancobrasil.com.br
		$a_01_5 = {68 73 62 63 2e 63 6f 6d 2e 62 72 } //1 hsbc.com.br
		$a_01_6 = {63 68 72 6f 6d 65 2e 65 78 65 } //1 chrome.exe
		$a_01_7 = {66 69 72 65 66 6f 78 2e 65 78 65 } //1 firefox.exe
		$a_01_8 = {70 67 75 61 72 64 2e 63 70 6c } //1 pguard.cpl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}