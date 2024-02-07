
rule TrojanSpy_Win32_Bancos_DV{
	meta:
		description = "TrojanSpy:Win32/Bancos.DV,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {41 72 71 75 69 76 6f 20 28 45 78 3a 20 54 6f 6b 65 6e 2c 20 43 44 2d 52 6f 6d 2c 20 64 69 73 71 75 65 74 65 } //01 00  Arquivo (Ex: Token, CD-Rom, disquete
		$a_01_1 = {62 6f 75 6e 64 61 72 79 3d 22 3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 65 6c } //01 00  boundary="=_NextPart_2rel
		$a_01_2 = {42 72 61 64 65 73 63 6f } //01 00  Bradesco
		$a_03_3 = {2a 2e 63 72 74 00 90 02 10 54 65 78 74 90 00 } //01 00 
		$a_01_4 = {6f 6e 66 69 72 6d 61 63 61 6f 50 61 67 61 6d 65 6e 74 6f 46 6f 72 6d } //01 00  onfirmacaoPagamentoForm
		$a_01_5 = {42 72 6f 77 73 65 72 20 41 6e 65 78 61 64 6f } //00 00  Browser Anexado
	condition:
		any of ($a_*)
 
}