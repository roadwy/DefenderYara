
rule TrojanSpy_Win32_Banker_AFD{
	meta:
		description = "TrojanSpy:Win32/Banker.AFD,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 43 66 ff 4c 24 04 75 c5 } //1
		$a_01_1 = {08 45 64 5f 54 75 72 6e 6f } //1
		$a_01_2 = {57 57 57 5f 47 65 74 57 69 6e 64 6f 77 49 6e 66 6f } //1 WWW_GetWindowInfo
		$a_01_3 = {43 68 61 76 65 20 64 65 20 53 65 67 75 72 61 6e } //1 Chave de Seguran
		$a_01_4 = {42 72 61 64 65 73 63 6f } //1 Bradesco
		$a_01_5 = {53 65 6e 68 61 } //1 Senha
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}