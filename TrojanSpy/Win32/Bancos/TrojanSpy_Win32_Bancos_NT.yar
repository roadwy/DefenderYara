
rule TrojanSpy_Win32_Bancos_NT{
	meta:
		description = "TrojanSpy:Win32/Bancos.NT,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_02_0 = {2f 69 6e 73 74 61 6c 6c 20 2f 73 69 6c 65 6e 74 90 05 05 01 00 73 63 20 73 74 61 72 74 20 } //3
		$a_00_1 = {63 66 67 5f 66 74 70 73 65 72 76 65 72 5f 75 70 64 2c 20 63 66 67 5f 66 74 70 75 73 65 72 5f 75 70 64 2c 20 63 66 67 5f 66 74 70 73 65 6e 68 61 5f 75 70 64 2c 20 63 66 67 5f 66 74 70 64 69 72 5f 75 70 64 } //2 cfg_ftpserver_upd, cfg_ftpuser_upd, cfg_ftpsenha_upd, cfg_ftpdir_upd
		$a_00_2 = {75 70 64 5f 6e 6f 6d 65 5f 6f 72 69 67 65 6d 2c 20 75 70 64 5f 6e 6f 6d 65 5f 64 65 73 74 69 6e 6f 2c 20 75 70 64 5f 76 65 72 73 61 6f 2c 20 75 70 64 5f 74 61 6d 61 6e 68 6f } //2 upd_nome_origem, upd_nome_destino, upd_versao, upd_tamanho
		$a_00_3 = {64 6f 77 6e 6c 6f 61 64 00 00 00 00 ff ff ff ff 05 00 00 00 74 65 78 74 6f 00 } //2
		$a_00_4 = {6e 6f 6d 65 00 00 00 00 ff ff ff ff 04 00 00 00 70 72 6f 70 00 } //2
		$a_00_5 = {5c 52 75 6e 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 00 } //1 剜湵坜湩潤獷䐠晥湥敤r
		$a_00_6 = {61 73 79 6e 63 65 71 6c 2e 69 6e 66 } //1 asynceql.inf
		$a_00_7 = {00 73 76 63 68 6f 73 74 00 } //1
	condition:
		((#a_02_0  & 1)*3+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}