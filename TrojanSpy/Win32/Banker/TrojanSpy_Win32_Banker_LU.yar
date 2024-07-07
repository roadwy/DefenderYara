
rule TrojanSpy_Win32_Banker_LU{
	meta:
		description = "TrojanSpy:Win32/Banker.LU,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 09 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 70 6c 75 67 61 63 65 66 2e 64 6c 6c } //15 c:\windows\system32\plugacef.dll
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_2 = {49 64 48 54 54 50 48 65 61 64 65 72 49 6e 66 6f } //5 IdHTTPHeaderInfo
		$a_01_3 = {54 49 64 53 53 4c 53 6f 63 6b 65 74 } //5 TIdSSLSocket
		$a_01_4 = {43 61 69 78 61 20 45 63 6f 6e } //5 Caixa Econ
		$a_01_5 = {55 53 45 52 2e 2e 3a 20 } //5 USER..: 
		$a_01_6 = {53 45 4e 48 41 2e 3a 20 } //5 SENHA.: 
		$a_01_7 = {63 6f 6e 74 65 75 64 6f 3d } //5 conteudo=
		$a_01_8 = {2d 00 20 00 43 00 61 00 64 00 61 00 73 00 74 00 72 00 61 00 6d 00 65 00 6e 00 74 00 6f 00 20 00 64 00 65 00 20 00 43 00 6f 00 6d 00 70 00 75 00 74 00 61 00 64 00 6f 00 72 00 } //5 - Cadastramento de Computador
	condition:
		((#a_01_0  & 1)*15+(#a_00_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5) >=50
 
}