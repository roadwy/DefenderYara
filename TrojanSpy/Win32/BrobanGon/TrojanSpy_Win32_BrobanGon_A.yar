
rule TrojanSpy_Win32_BrobanGon_A{
	meta:
		description = "TrojanSpy:Win32/BrobanGon.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 54 69 74 75 6c 6f 42 72 61 64 65 73 63 6f } //01 00  tTituloBradesco
		$a_01_1 = {74 53 61 6e 74 61 6e 64 65 72 } //01 00  tSantander
		$a_01_2 = {74 54 69 74 75 6c 6f 48 73 62 63 4a 75 72 69 64 69 63 6f } //01 00  tTituloHsbcJuridico
		$a_01_3 = {74 54 69 74 75 6c 6f 53 69 63 6f 6f 62 } //01 00  tTituloSicoob
		$a_01_4 = {74 56 65 6e 63 69 6d 65 6e 74 6f } //01 00  tVencimento
		$a_01_5 = {74 78 74 4e 6f 76 61 4c 69 6e 68 61 } //01 00  txtNovaLinha
		$a_01_6 = {44 00 61 00 74 00 61 00 56 00 65 00 6e 00 63 00 69 00 6d 00 65 00 6e 00 74 00 6f 00 } //01 00  DataVencimento
		$a_01_7 = {62 00 6f 00 6c 00 65 00 74 00 6f 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 61 00 64 00 6f 00 44 00 64 00 61 00 46 00 6f 00 72 00 6d 00 } //00 00  boletoRegistradoDdaForm
		$a_00_8 = {5d 04 00 } //00 d0 
	condition:
		any of ($a_*)
 
}