
rule TrojanSpy_Win32_Banker_LT{
	meta:
		description = "TrojanSpy:Win32/Banker.LT,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 08 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {49 64 48 54 54 50 48 65 61 64 65 72 49 6e 66 6f } //5 IdHTTPHeaderInfo
		$a_01_2 = {54 49 64 53 53 4c 53 6f 63 6b 65 74 } //5 TIdSSLSocket
		$a_01_3 = {43 61 69 78 61 20 45 63 6f 6e 6f 6d 69 63 61 20 46 65 64 65 72 61 6c } //5 Caixa Economica Federal
		$a_01_4 = {43 50 46 20 49 6e 76 61 6c 69 64 6f 2e } //5 CPF Invalido.
		$a_01_5 = {53 65 6e 68 61 20 64 65 20 34 20 64 69 67 69 74 6f 73 20 69 6e 63 6f 72 72 65 74 61 2e } //5 Senha de 4 digitos incorreta.
		$a_01_6 = {42 61 6e 63 6f 20 64 6f 20 62 72 61 73 69 6c } //5 Banco do brasil
		$a_01_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 61 69 78 61 2e 67 6f 76 2e 62 72 20 2d 20 43 61 } //1 http://www.caixa.gov.br - Ca
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*1) >=41
 
}