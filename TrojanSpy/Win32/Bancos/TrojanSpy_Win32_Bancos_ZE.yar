
rule TrojanSpy_Win32_Bancos_ZE{
	meta:
		description = "TrojanSpy:Win32/Bancos.ZE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b7 1a 0f bf 31 0f af de 81 c3 00 08 00 00 8b 74 24 24 c1 fb 0c 83 c1 02 89 1e 83 c2 02 83 44 24 24 04 40 83 f8 40 7c } //01 00 
		$a_00_1 = {2f 6f 66 66 6c 69 6e 65 5f 6e 65 74 61 74 6d 2e 70 68 70 3f 6e 74 69 64 70 63 3d } //01 00  /offline_netatm.php?ntidpc=
		$a_00_2 = {50 6f 72 20 66 61 76 6f 72 20 61 67 75 61 72 64 65 20 6f 20 70 72 6f 63 65 73 73 61 6d 65 6e 74 6f } //01 00  Por favor aguarde o processamento
		$a_00_3 = {62 72 61 64 65 73 63 6f } //01 00  bradesco
		$a_00_4 = {65 78 70 6c 6f 72 65 72 5c 62 72 6f 77 73 65 72 20 68 65 6c 70 65 72 20 6f 62 6a 65 63 74 73 } //00 00  explorer\browser helper objects
	condition:
		any of ($a_*)
 
}