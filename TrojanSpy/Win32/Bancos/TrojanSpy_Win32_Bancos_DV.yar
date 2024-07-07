
rule TrojanSpy_Win32_Bancos_DV{
	meta:
		description = "TrojanSpy:Win32/Bancos.DV,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 72 71 75 69 76 6f 20 28 45 78 3a 20 54 6f 6b 65 6e 2c 20 43 44 2d 52 6f 6d 2c 20 64 69 73 71 75 65 74 65 } //10 Arquivo (Ex: Token, CD-Rom, disquete
		$a_01_1 = {62 6f 75 6e 64 61 72 79 3d 22 3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 65 6c } //1 boundary="=_NextPart_2rel
		$a_01_2 = {42 72 61 64 65 73 63 6f } //1 Bradesco
		$a_03_3 = {2a 2e 63 72 74 00 90 02 10 54 65 78 74 90 00 } //1
		$a_01_4 = {6f 6e 66 69 72 6d 61 63 61 6f 50 61 67 61 6d 65 6e 74 6f 46 6f 72 6d } //1 onfirmacaoPagamentoForm
		$a_01_5 = {42 72 6f 77 73 65 72 20 41 6e 65 78 61 64 6f } //1 Browser Anexado
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=11
 
}