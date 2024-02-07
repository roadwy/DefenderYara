
rule TrojanSpy_Win32_Bancos_QX{
	meta:
		description = "TrojanSpy:Win32/Bancos.QX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {66 83 c6 06 0f 80 2f 01 00 00 66 83 fe 08 0f 8c a3 00 00 00 66 83 ee 08 0f bf fb 90 01 26 99 f7 f9 8b ca ff d3 90 00 } //01 00 
		$a_01_1 = {46 00 47 00 31 00 32 00 66 00 69 00 48 00 6d 00 6e 00 49 00 74 00 75 00 76 00 77 00 78 00 } //01 00  FG12fiHmnItuvwx
		$a_01_2 = {53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 4a 00 75 00 6c 00 69 00 61 00 6e 00 61 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 } //01 00  Settings\Juliana\Desktop
		$a_01_3 = {53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 63 00 61 00 62 00 65 00 63 00 61 00 6f 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 } //01 00  Settings\cabecao\Desktop
		$a_00_4 = {61 00 5f 00 61 00 5f 00 61 00 5f 00 70 00 72 00 6f 00 6a 00 65 00 74 00 6f 00 73 00 5c 00 62 00 62 00 5f 00 66 00 69 00 73 00 69 00 63 00 6f 00 5f 00 67 00 66 00 5c 00 4e 00 4f 00 56 00 4f 00 5f 00 50 00 55 00 58 00 41 00 } //00 00  a_a_a_projetos\bb_fisico_gf\NOVO_PUXA
	condition:
		any of ($a_*)
 
}