
rule TrojanSpy_Win32_Bancos_QF{
	meta:
		description = "TrojanSpy:Win32/Bancos.QF,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6f 20 42 72 61 64 65 73 63 6f 20 49 6e 74 65 72 6e 65 74 20 42 61 6e 6b 69 6e 67 2c } //01 00  do Bradesco Internet Banking,
		$a_01_1 = {54 65 63 6c 61 64 6f 20 56 69 72 74 75 61 6c } //01 00  Teclado Virtual
		$a_01_2 = {64 69 67 69 74 61 64 61 73 2e } //01 00  digitadas.
		$a_01_3 = {53 42 4b 65 79 44 6f 77 6e } //01 00  SBKeyDown
		$a_01_4 = {43 68 61 76 65 20 64 65 20 53 65 67 75 72 61 6e } //01 00  Chave de Seguran
		$a_01_5 = {33 20 64 69 67 69 74 6f 73 20 64 61 73 20 63 68 61 76 65 73 } //00 00  3 digitos das chaves
	condition:
		any of ($a_*)
 
}