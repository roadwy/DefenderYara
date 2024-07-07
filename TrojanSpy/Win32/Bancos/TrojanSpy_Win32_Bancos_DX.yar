
rule TrojanSpy_Win32_Bancos_DX{
	meta:
		description = "TrojanSpy:Win32/Bancos.DX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 00 78 00 74 00 30 00 31 00 42 00 72 00 61 00 6e 00 63 00 68 00 44 00 69 00 67 00 69 00 74 00 } //1 txt01BranchDigit
		$a_01_1 = {74 00 78 00 74 00 30 00 32 00 41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 } //1 txt02Account
		$a_01_2 = {63 00 61 00 69 00 78 00 61 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //1 caixa.com.br
		$a_01_3 = {53 00 4d 00 54 00 50 00 20 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //1 SMTP connection
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}