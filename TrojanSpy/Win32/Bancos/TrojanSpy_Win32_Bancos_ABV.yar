
rule TrojanSpy_Win32_Bancos_ABV{
	meta:
		description = "TrojanSpy:Win32/Bancos.ABV,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 69 74 65 6e 65 74 2e 73 65 72 61 73 61 2e 63 6f 6d 2e 62 72 2f 65 6c 65 6d 65 6e 74 6f 73 5f 65 73 74 72 75 74 75 72 61 2f 6c 6f 67 69 6e } //01 00  sitenet.serasa.com.br/elementos_estrutura/login
		$a_01_1 = {73 61 6e 74 61 6e 64 65 72 2e 63 6f 6d 2e 62 72 2f 70 6f 72 74 61 6c 2f 77 70 73 2f 73 63 72 69 70 74 } //01 00  santander.com.br/portal/wps/script
		$a_01_2 = {69 00 62 00 32 00 2e 00 62 00 72 00 61 00 64 00 65 00 73 00 63 00 6f 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 69 00 62 00 70 00 66 00 6c 00 6f 00 67 00 69 00 6e 00 } //01 00  ib2.bradesco.com.br/ibpflogin
		$a_01_3 = {62 61 6e 6b 6c 69 6e 65 2e 69 74 61 75 2e 63 6f 6d 2e 62 72 2f 6c 67 6e 65 74 } //02 00  bankline.itau.com.br/lgnet
		$a_01_4 = {be 01 00 00 00 8d 45 f0 8b 55 fc 8a 54 32 ff 8b cf 2a d1 e8 } //02 00 
		$a_01_5 = {40 89 45 f0 c7 45 f4 00 00 00 00 8d 4d f8 8b 83 70 03 00 00 8b 55 f4 8b 38 ff 57 0c 8d 8d bc fe ff ff ba f4 01 00 00 } //02 00 
		$a_01_6 = {8b 55 fc 8b c3 8b 08 ff 51 38 8d 4d f0 ba f4 01 00 00 b8 } //00 00 
	condition:
		any of ($a_*)
 
}