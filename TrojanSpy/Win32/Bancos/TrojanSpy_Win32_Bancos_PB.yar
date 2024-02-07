
rule TrojanSpy_Win32_Bancos_PB{
	meta:
		description = "TrojanSpy:Win32/Bancos.PB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 72 61 64 65 73 63 6f } //01 00  Bradesco
		$a_01_1 = {46 72 61 73 65 20 73 65 63 72 65 74 61 } //01 00  Frase secreta
		$a_01_2 = {43 6f 6e 74 61 20 43 6f 72 72 65 6e 74 65 } //01 00  Conta Corrente
		$a_01_3 = {44 49 47 49 54 45 20 54 4f 44 41 53 } //01 00  DIGITE TODAS
		$a_01_4 = {45 2d 42 61 6e 6b 69 6e 67 20 69 6e 73 74 61 6c 61 64 6f } //03 00  E-Banking instalado
		$a_01_5 = {4e 65 78 74 50 61 72 74 5f 32 61 6c 74 72 66 6b 69 6e 64 79 } //03 00  NextPart_2altrfkindy
		$a_01_6 = {76 69 73 61 74 2e 63 6f 6d 2e 62 72 } //00 00  visat.com.br
	condition:
		any of ($a_*)
 
}