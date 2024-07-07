
rule TrojanSpy_Win32_Banker_RQ{
	meta:
		description = "TrojanSpy:Win32/Banker.RQ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_02_0 = {c1 e0 06 03 d8 89 90 01 02 83 c7 06 83 ff 08 7c 90 01 01 83 ef 08 8b cf 8b 90 01 02 d3 eb 8b cf b8 01 00 00 00 d3 e0 8b c8 8b 90 01 02 99 f7 f9 90 00 } //1
		$a_00_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 6d 73 6e 6d 73 67 72 2e 65 78 65 20 2f 66 } //1 taskkill /im msnmsgr.exe /f
		$a_00_2 = {6d 61 69 6c 2e 74 65 72 72 61 2e 63 6f 6d 2e 62 72 } //1 mail.terra.com.br
		$a_00_3 = {73 65 6e 68 61 } //1 senha
		$a_00_4 = {2d 20 50 61 79 50 61 6c 20 2d } //1 - PayPal -
		$a_00_5 = {53 65 6a 61 20 62 65 6d 2d 76 69 6e 64 6f 28 61 29 20 61 6f 20 46 61 63 65 62 6f 6f 6b } //1 Seja bem-vindo(a) ao Facebook
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}