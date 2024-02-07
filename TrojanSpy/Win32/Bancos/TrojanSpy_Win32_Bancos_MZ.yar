
rule TrojanSpy_Win32_Bancos_MZ{
	meta:
		description = "TrojanSpy:Win32/Bancos.MZ,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1e 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {41 72 71 75 69 76 6f 20 28 45 78 3a 20 54 6f 6b 65 6e 2c 20 43 44 2d 52 6f 6d 2c 20 64 69 73 71 75 65 74 65 } //0a 00  Arquivo (Ex: Token, CD-Rom, disquete
		$a_01_1 = {42 72 61 64 65 73 63 6f } //0a 00  Bradesco
		$a_02_2 = {2d 00 2d 00 4e 00 65 00 78 00 74 00 4d 00 69 00 6d 00 65 00 50 00 61 00 72 00 74 00 90 02 08 42 00 61 00 6e 00 63 00 6f 00 90 00 } //01 00 
		$a_00_3 = {4e 00 6f 00 72 00 74 00 6f 00 6e 00 20 00 52 00 65 00 63 00 65 00 62 00 65 00 75 00 20 00 30 00 20 00 2d 00 20 00 66 00 72 00 6d 00 5f 00 53 00 65 00 72 00 76 00 69 00 } //00 00  Norton Recebeu 0 - frm_Servi
	condition:
		any of ($a_*)
 
}