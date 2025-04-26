
rule TrojanSpy_Win32_Bancrat_A{
	meta:
		description = "TrojanSpy:Win32/Bancrat.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0c 00 00 "
		
	strings :
		$a_81_0 = {43 4c 49 45 4e 54 45 20 52 45 4d 4f 54 45 20 58 20 4c 45 54 4f } //1 CLIENTE REMOTE X LETO
		$a_01_1 = {4d 4f 44 5f 47 45 54 53 43 52 45 45 4e } //1 MOD_GETSCREEN
		$a_01_2 = {4d 4f 44 5f 43 4f 4d 50 41 43 54 41 5f 49 4d 47 } //1 MOD_COMPACTA_IMG
		$a_01_3 = {4d 4f 44 5f 6d 4f 74 68 65 72 42 72 6f 77 73 65 72 } //1 MOD_mOtherBrowser
		$a_01_4 = {49 6d 67 42 42 41 67 75 61 72 64 } //1 ImgBBAguard
		$a_01_5 = {49 6d 67 42 72 41 76 69 73 6f } //1 ImgBrAviso
		$a_01_6 = {49 6d 67 48 73 56 6f 6c 74 61 72 } //1 ImgHsVoltar
		$a_01_7 = {49 6d 67 53 74 43 6f 6e 74 61 74 6f } //1 ImgStContato
		$a_01_8 = {49 6d 67 53 69 63 72 61 43 6f 64 69 67 6f } //1 ImgSicraCodigo
		$a_01_9 = {49 6d 67 43 45 46 49 64 65 6e 74 69 66 69 63 61 55 73 65 72 } //1 ImgCEFIdentificaUser
		$a_01_10 = {49 6d 67 49 54 47 65 74 44 6e 73 } //1 ImgITGetDns
		$a_01_11 = {53 6f 6c 69 63 69 74 53 65 6e 68 61 } //1 SolicitSenha
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=5
 
}