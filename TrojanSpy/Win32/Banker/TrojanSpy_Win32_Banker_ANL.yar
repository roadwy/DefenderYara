
rule TrojanSpy_Win32_Banker_ANL{
	meta:
		description = "TrojanSpy:Win32/Banker.ANL,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 4d 45 52 49 43 41 4e 41 53 } //01 00  AMERICANAS
		$a_01_1 = {4f 70 65 72 61 64 6f 72 61 2e 3a } //01 00  Operadora.:
		$a_01_2 = {55 73 75 61 72 69 6f 2e 2e 2e 3a } //01 00  Usuario...:
		$a_01_3 = {53 65 6e 68 61 2e 2e 2e 2e 2e 3a } //01 00  Senha.....:
		$a_01_4 = {4e 6f 6d 65 20 43 61 72 74 61 6f 2e 2e 2e 2e 3a } //01 00  Nome Cartao....:
		$a_01_5 = {4e 75 6d 65 72 6f 20 43 61 72 64 2e 2e 2e 2e 3a } //01 00  Numero Card....:
		$a_01_6 = {56 61 6c 69 64 61 64 65 2e 2e 2e 2e 2e 2e 2e 3a } //01 00  Validade.......:
		$a_01_7 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c } //01 00  SOFTWARE\Borland\Delphi\
		$a_01_8 = {8b 0e 8b 1f 38 d9 75 41 4a 74 17 38 fd 75 3a 4a 74 10 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75 27 } //00 00 
	condition:
		any of ($a_*)
 
}