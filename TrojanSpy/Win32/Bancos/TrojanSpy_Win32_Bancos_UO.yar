
rule TrojanSpy_Win32_Bancos_UO{
	meta:
		description = "TrojanSpy:Win32/Bancos.UO,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 69 67 69 74 65 20 73 75 61 20 73 65 6e 68 61 20 64 65 20 34 20 64 } //02 00  Digite sua senha de 4 d
		$a_01_1 = {42 72 61 64 65 73 63 6f 20 62 79 20 44 34 52 69 4f } //01 00  Bradesco by D4RiO
		$a_01_2 = {67 69 74 6f 73 2e 20 50 6f 72 20 66 61 76 6f 72 2c 20 75 74 69 6c 69 7a 65 20 6f 20 54 65 63 6c 61 64 6f 20 56 69 72 74 75 61 6c 2e } //01 00  gitos. Por favor, utilize o Teclado Virtual.
		$a_01_3 = {49 6e 66 6f 72 6d 65 20 73 75 61 20 66 72 61 73 65 20 73 65 63 72 65 74 61 } //01 00  Informe sua frase secreta
		$a_01_4 = {4f 20 42 61 6e 63 6f 20 42 72 61 64 65 73 63 6f 20 61 67 72 61 64 65 63 65 20 61 20 73 75 61 20 63 6f 6c 61 62 6f 72 61 } //00 00  O Banco Bradesco agradece a sua colabora
	condition:
		any of ($a_*)
 
}