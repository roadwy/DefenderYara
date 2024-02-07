
rule TrojanSpy_Win32_Bancos_BK{
	meta:
		description = "TrojanSpy:Win32/Bancos.BK,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {50 72 6f 76 69 64 65 72 3d 53 51 4c 4f 4c 45 44 42 2e 31 3b 50 61 73 73 77 6f 72 64 3d } //01 00  Provider=SQLOLEDB.1;Password=
		$a_01_1 = {6a 61 76 61 73 63 72 69 70 74 3a 65 6e 76 69 61 55 72 6c } //01 00  javascript:enviaUrl
		$a_01_2 = {45 6e 76 69 61 72 70 67 69 6e 61 } //01 00  Enviarpgina
		$a_01_3 = {57 69 6e 64 6f 77 73 20 6d 65 73 73 65 6e 67 65 72 } //01 00  Windows messenger
		$a_01_4 = {6a 61 76 61 73 63 72 69 70 74 3a 63 61 64 61 73 74 72 6f 53 65 6e 68 61 73 28 29 } //01 00  javascript:cadastroSenhas()
		$a_01_5 = {5c 6c 69 62 65 72 61 70 6c 75 67 2e 6c 6f 67 } //00 00  \liberaplug.log
	condition:
		any of ($a_*)
 
}