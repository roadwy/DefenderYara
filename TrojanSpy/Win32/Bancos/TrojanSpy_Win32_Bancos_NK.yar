
rule TrojanSpy_Win32_Bancos_NK{
	meta:
		description = "TrojanSpy:Win32/Bancos.NK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 72 71 75 69 76 6f 20 28 45 78 3a 20 54 6f 6b 65 6e 2c 20 43 44 2d 52 6f 6d 2c 20 64 69 73 71 75 65 74 65 } //01 00  Arquivo (Ex: Token, CD-Rom, disquete
		$a_01_1 = {5b 41 6c 74 65 72 61 72 53 61 6e 74 61 54 61 62 65 6c 61 4f 4b 5d } //01 00  [AlterarSantaTabelaOK]
		$a_01_2 = {6d 61 63 61 64 64 72 65 73 73 3d } //01 00  macaddress=
		$a_01_3 = {42 72 61 64 65 73 63 6f } //00 00  Bradesco
	condition:
		any of ($a_*)
 
}