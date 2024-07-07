
rule TrojanSpy_Win32_Bancos_AES{
	meta:
		description = "TrojanSpy:Win32/Bancos.AES,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 61 6e 38 31 39 32 2e 76 78 64 } //2 lan8192.vxd
		$a_01_1 = {74 69 70 6f 43 6f 6e 74 61 44 65 73 74 69 6e 6f } //2 tipoContaDestino
		$a_01_2 = {42 61 6e 63 6f 20 44 65 20 44 61 64 6f 73 20 4d 6f 6e 69 74 6f 72 } //3 Banco De Dados Monitor
		$a_01_3 = {55 70 64 61 74 65 20 74 62 6c 5f 30 30 31 66 5f 65 78 74 72 61 74 6f 20 53 65 74 20 72 65 73 70 6f 73 74 61 20 3d 20 } //3 Update tbl_001f_extrato Set resposta = 
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=10
 
}