
rule TrojanSpy_Win32_KLRemote{
	meta:
		description = "TrojanSpy:Win32/KLRemote,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_81_0 = {53 65 72 76 69 64 6f 72 20 2d 20 4f 70 65 72 61 64 6f 72 } //1 Servidor - Operador
		$a_81_1 = {54 69 6d 65 4f 75 74 } //1 TimeOut
		$a_81_2 = {4d 61 78 43 6f 6e 2e } //1 MaxCon.
		$a_81_3 = {50 6f 72 74 61 } //1 Porta
		$a_81_4 = {53 65 6e 68 61 } //1 Senha
		$a_81_5 = {44 65 73 61 74 69 76 61 72 20 4f 70 65 72 61 64 6f 72 } //1 Desativar Operador
		$a_81_6 = {53 69 73 74 65 6d 20 4f 70 65 72 61 63 69 6f 6e 61 6c } //1 Sistem Operacional
		$a_81_7 = {50 72 6f 63 65 73 73 61 64 6f 72 } //1 Processador
		$a_81_8 = {52 65 67 69 73 74 72 6f 20 64 65 20 4c 6f 67 } //1 Registro de Log
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=6
 
}